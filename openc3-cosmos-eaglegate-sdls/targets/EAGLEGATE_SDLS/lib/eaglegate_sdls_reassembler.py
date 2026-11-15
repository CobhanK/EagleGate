"""Space packets out of the data fields of accepted frames, per virtual channel.

Packets may span frames: the spacecraft (e.g. NOS3's TO app) fills each frame
and continues the packet in the next frame of the same virtual channel. The
first header pointer (FHP) says where the first packet starting in a frame
begins, so after a lost frame the reassembler drops the broken packet and
picks up again at the next frame's FHP.

Nothing incomplete or inconsistent is passed on: it is returned as a "drop"
with the reason, for the quarantine. Only whole packets with a sane CCSDS
header come out, and each carries what the frames it came in guaranteed (the
weakest, when it spans frames with different protection).
"""
from dataclasses import dataclass, field

from eaglegate_sdls_link_config import PROTECTIONS
from eaglegate_sdls_tm_frame import FHP_NO_PACKET_START, FHP_ONLY_IDLE

HEADER = 6
IDLE_APID = 0x7FF
MAX_CCSDS_PACKET = 65542


@dataclass
class FrameInfo:
    """What one frame contributes to the packets in it."""
    vcid: int
    spi: int
    protection: str
    vc_count: int
    mc_count: int


@dataclass
class _Partial:
    data: bytearray
    frames: list = field(default_factory=list)  # FrameInfo of each frame it came in

    def total_length(self):
        if len(self.data) < HEADER:
            return None
        return ((self.data[4] << 8) | self.data[5]) + 1 + HEADER


def weakest(frames):
    """The FrameInfo whose protection is weakest (PROTECTIONS is ordered)."""
    return min(frames, key=lambda f: PROTECTIONS.index(f.protection))


def link_values(frames):
    """The link values the firewall sees for a packet (eaglegate_extensions)."""
    weak = weakest(frames)
    return {"vcid": frames[0].vcid, "spi": weak.spi, "protection": weak.protection,
            "frames": len(frames), "vc_count": frames[0].vc_count, "mc_count": frames[0].mc_count}


class Reassembler:
    def __init__(self, max_packet, keep_idle=False):
        self.max_packet = max_packet
        self.keep_idle = keep_idle
        self.partials = {}     # vcid -> _Partial
        self.idle_packets = 0
        self.oid_frames = 0

    def reset(self):
        self.partials = {}

    def drop_partial(self, vcid, reason):
        """Discard the packet in progress on a virtual channel (e.g. after a frame
        gap). Returns a list with one drop, or an empty list."""
        partial = self.partials.pop(vcid, None)
        if partial is None:
            return []
        return [(bytes(partial.data), reason, partial.frames)]

    def add(self, info, fhp, data):
        """One accepted frame's data field. Returns (packets, drops):
          packets: [(packet_bytes, frames)]  frames = FrameInfo list
          drops:   [(bytes, reason, frames)]"""
        packets, drops = [], []
        vcid = info.vcid
        if fhp == FHP_ONLY_IDLE:
            self.oid_frames += 1
            return packets, drops

        partial = self.partials.get(vcid)
        if fhp == FHP_NO_PACKET_START:
            if partial is None:
                drops.append((bytes(data), "frame continues a packet whose start was lost", [info]))
                return packets, drops
            self._continue(vcid, partial, info, data, True, packets, drops)
            return packets, drops

        head, rest = data[:fhp], data[fhp:]
        if partial is not None:
            self._continue(vcid, partial, info, head, False, packets, drops)
        elif head:
            drops.append((bytes(head), "end of a packet whose start was lost", [info]))
        self._packets_from(vcid, info, rest, packets, drops)
        return packets, drops

    def _continue(self, vcid, partial, info, data, whole_field, packets, drops):
        """Add bytes to the packet in progress. whole_field: the frame's FHP said no
        packet starts in it, so the packet may not end before the field does;
        otherwise `data` is exactly what is left of it before the next packet."""
        partial.data += data
        partial.frames.append(info)
        total = partial.total_length()
        if total is not None:
            problem = self._header_problem(partial.data, total)
            if problem:
                del self.partials[vcid]
                drops.append((bytes(partial.data), problem, partial.frames))
                return
            if len(partial.data) > total or (not whole_field and len(partial.data) != total):
                del self.partials[vcid]
                where = "inside a frame that says no packet starts in it" if whole_field else \
                    "where the frame's first header pointer says the next packet starts"
                drops.append((bytes(partial.data), f"packet of {total} bytes does not end {where} "
                                                   f"(has {len(partial.data)})", partial.frames))
                return
            if len(partial.data) == total:
                del self.partials[vcid]
                self._emit(bytes(partial.data), partial.frames, packets)
                return
        elif not whole_field:
            # The next packet starts here, but this one's header is still incomplete
            del self.partials[vcid]
            drops.append((bytes(partial.data), "packet header cut off by the next packet", partial.frames))

    def _packets_from(self, vcid, info, data, packets, drops):
        pos = 0
        while pos < len(data):
            rest = data[pos:]
            if len(rest) < HEADER:
                self.partials[vcid] = _Partial(bytearray(rest), [info])
                return
            total = ((rest[4] << 8) | rest[5]) + 1 + HEADER
            problem = self._header_problem(rest, total)
            if problem:
                # The lengths can no longer be trusted: drop the rest of this
                # field; the next frame's FHP resynchronises
                drops.append((bytes(rest), problem, [info]))
                return
            if len(rest) < total:
                self.partials[vcid] = _Partial(bytearray(rest), [info])
                return
            self._emit(bytes(rest[:total]), [info], packets)
            pos += total

    def _header_problem(self, data, total):
        version = data[0] >> 5
        if version != 0:
            return f"not a CCSDS space packet (version {version}) where a packet should start"
        # Idle packets that are dropped anyway may be as long as the spacecraft
        # likes (NOS3 fills frames with idle packets of up to a frame's size);
        # every other packet must fit what the firewall accepts
        idle = (((data[0] & 0x07) << 8) | data[1]) == IDLE_APID and not self.keep_idle
        limit = MAX_CCSDS_PACKET if idle else self.max_packet
        if total > limit:
            return f"packet declares {total} bytes, more than the {limit}-byte limit"
        return None

    def _emit(self, packet, frames, packets):
        apid = ((packet[0] & 0x07) << 8) | packet[1]
        if apid == IDLE_APID and not self.keep_idle:
            self.idle_packets += 1
            return
        packets.append((packet, frames))
