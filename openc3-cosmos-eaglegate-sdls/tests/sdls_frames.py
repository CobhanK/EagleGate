"""Build TM transfer frames the way a spacecraft does, for the tests.

FrameBuilder packs space packets into fixed-length frames like NOS3's TO app:
packets are written back to back, a packet that does not fit continues in the
next frame of the same virtual channel, the first header pointer says where
the first packet starting in a frame begins, and a frame is filled up with an
idle packet when there is nothing more to send.
"""
from dataclasses import dataclass

from eaglegate_sdls_tm_frame import (FECF_BYTES, FHP_NO_PACKET_START, FHP_ONLY_IDLE, OCF_BYTES,
                                     PRIMARY_HEADER_BYTES, SPI_BYTES, crc16, derandomize)

ASM = bytes.fromhex("1ACFFC1D")
NOS3 = {"scid": 3, "frame_length": 1786}
# NOS3's SAs (Crypto_SC_Init): (iv_len, sn_len, pl_len, mac_len)
LAYOUTS = {5: (12, 0, 0, 0), 6: (12, 0, 0, 0), 7: (0, 2, 0, 16)}


def packet(apid, payload=b"\x00", seq=0, packet_type=0, sec_hdr=0, version=0):
    word1 = (version << 13) | (packet_type << 12) | (sec_hdr << 11) | apid
    word2 = (0b11 << 14) | (seq & 0x3FFF)
    return word1.to_bytes(2, "big") + word2.to_bytes(2, "big") + (len(payload) - 1).to_bytes(2, "big") + payload


def idle_packet(total_length):
    """An idle packet (APID 0x7FF) of exactly total_length bytes (>= 7)."""
    return packet(0x7FF, bytes([0x55]) * (total_length - 6))


def primary_header(scid, vcid, mc_count, vc_count, fhp, ocf=0, sec_hdr=0, version=0, sync=0, order=0, seg=3):
    word0 = (version << 14) | (scid << 4) | (vcid << 1) | ocf
    status = (sec_hdr << 15) | (sync << 14) | (order << 13) | (seg << 11) | fhp
    return word0.to_bytes(2, "big") + bytes([mc_count & 0xFF, vc_count & 0xFF]) + status.to_bytes(2, "big")


@dataclass
class Layout:
    frame_length: int = 1786
    iv_len: int = 12
    sn_len: int = 0
    pl_len: int = 0
    mac_len: int = 0
    has_ocf: bool = False
    has_fecf: bool = False
    secondary_header: bytes = b""   # whole secondary header incl. its ID byte, or b""

    @classmethod
    def for_spi(cls, spi, **kwargs):
        iv, sn, pl, mac = LAYOUTS[spi]
        return cls(iv_len=iv, sn_len=sn, pl_len=pl, mac_len=mac, **kwargs)

    def data_length(self):
        return (self.frame_length - PRIMARY_HEADER_BYTES - len(self.secondary_header) - SPI_BYTES - self.iv_len
                - self.sn_len - self.pl_len - self.mac_len - (OCF_BYTES if self.has_ocf else 0)
                - (FECF_BYTES if self.has_fecf else 0))


def build_frame(data_field, fhp, spi=5, scid=3, vcid=1, mc_count=0, vc_count=0, layout=None, iv=None, sn=None,
                pl=0, mac=None, ocf=b"\x00" * 4, **header_overrides):
    """One frame; data_field must be exactly layout.data_length() bytes."""
    layout = layout or Layout.for_spi(spi)
    assert len(data_field) == layout.data_length(), (len(data_field), layout.data_length())
    header = primary_header(scid, vcid, mc_count, vc_count, fhp, ocf=int(layout.has_ocf),
                            sec_hdr=int(bool(layout.secondary_header)), **header_overrides)
    iv_bytes = (iv if isinstance(iv, bytes) else (iv or 0).to_bytes(layout.iv_len, "big")) if layout.iv_len else b""
    sn_bytes = (sn or 0).to_bytes(layout.sn_len, "big") if layout.sn_len else b""
    pl_bytes = pl.to_bytes(layout.pl_len, "big") if layout.pl_len else b""
    mac_bytes = (mac or bytes(range(layout.mac_len)))[:layout.mac_len]
    frame = (header + layout.secondary_header + spi.to_bytes(2, "big") + iv_bytes + sn_bytes + pl_bytes
             + bytes(data_field) + mac_bytes + (ocf if layout.has_ocf else b""))
    if layout.has_fecf:
        frame += crc16(frame).to_bytes(2, "big")
    assert len(frame) == layout.frame_length
    return frame


class FrameBuilder:
    """Packs packets into frames on one virtual channel, keeping its counters."""

    def __init__(self, spi=5, vcid=1, scid=3, layout=None, counter_start=1, asm=ASM, randomize=False):
        self.spi = spi
        self.vcid = vcid
        self.scid = scid
        self.layout = layout or Layout.for_spi(spi)
        self.vc_count = 0
        self.mc_count = 0
        self.counter = counter_start     # SN or IV value of the next frame
        self.pending = bytearray()       # bytes of packets not yet framed
        self.pending_starts = []         # offsets in pending where a packet starts
        self.asm = asm
        self.randomize = randomize

    def add(self, *packets):
        for item in packets:
            self.pending_starts.append(len(self.pending))
            self.pending += item
        return self

    def frames(self, flush=True):
        """Frames for everything added; with flush, the last one is filled with an idle packet."""
        out = []
        size = self.layout.data_length()
        while len(self.pending) >= size or (flush and self.pending):
            if len(self.pending) < size:
                filler = size - len(self.pending)
                if filler >= 7:
                    self.add(idle_packet(filler))
                else:  # too small for an idle packet: start one that continues next frame
                    self.add(idle_packet(filler + size))
            field = bytes(self.pending[:size])
            starts = [s for s in self.pending_starts if s < size]
            fhp = starts[0] if starts else FHP_NO_PACKET_START
            out.append(self._frame(field, fhp))
            del self.pending[:size]
            self.pending_starts = [s - size for s in self.pending_starts if s >= size]
        return out

    def oid_frame(self):
        size = self.layout.data_length()
        return self._frame(idle_packet(size)[:size], FHP_ONLY_IDLE)

    def _frame(self, field, fhp, **overrides):
        options = dict(spi=self.spi, scid=self.scid, vcid=self.vcid, mc_count=self.mc_count,
                       vc_count=self.vc_count, layout=self.layout)
        if self.layout.sn_len:
            options["sn"] = self.counter
        if self.layout.iv_len:
            options["iv"] = self.counter
        options.update(overrides)
        frame = build_frame(field, fhp, **options)
        self.vc_count = (self.vc_count + 1) % 256
        self.mc_count = (self.mc_count + 1) % 256
        self.counter += 1
        return frame

    def cadu(self, frame):
        return self.asm + (derandomize(frame) if self.randomize else frame)

    def cadus(self, flush=True):
        return [self.cadu(f) for f in self.frames(flush)]
