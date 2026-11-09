"""The checks every frame must pass, in order, before its packets are used.

  1  frame length                       frame   decides trust
  2  FECF (CRC), when configured        frame   corruption: never decides trust
  3  version 0 (TM)                     frame   decides trust
  4  spacecraft ID                      frame   decides trust
  5  virtual channel configured         frame   decides trust
  6  OCF and secondary header flags     frame   decides trust
  7  packet mode (sync/order/seg. len.) frame   decides trust
  8  SPI configured AND allowed on      sdls    decides trust   <- the downgrade
     this virtual channel                                          CryptoLib allows
  9  frame long enough for the SA       sdls    decides trust
 10  first header pointer in range      frame   decides trust
 11  crypto backend (Phase 1: none)     sdls    only a failed MAC decides trust
 12  anti-replay                        sdls    never decides trust
 13  virtual channel frame count        frame   never; "warn" by default

"Decides trust": as a connection's FIRST frame, this rejection means the sender
is not the spacecraft we expect, so the connection becomes untrusted (when
link.untrust_on_first_frame_reject is on). Corruption, replays and gaps happen
on real links and say nothing about who is sending.

check() never changes state; commit() records an accepted frame (frame counts
and the anti-replay counter), so a rejected frame cannot move anything.
"""
from dataclasses import dataclass, field

from eaglegate_sdls_frame_security import (CLEAR, DECRYPTED, FAILED, UNAVAILABLE, UNREADABLE, UNVERIFIED,
                                           VERIFIED)
from eaglegate_sdls_tm_frame import (FHP_NO_PACKET_START, FHP_ONLY_IDLE, FRAME_COUNT_MODULO, FrameError,
                                     PrimaryHeader, fecf_ok, parse_tm_frame, read_spi)

COUNTERS = ("frames", "accepted", "rejected", "fecf_errors", "vc_count_gaps", "mc_count_gaps",
            "replay_rejections", "unverified", "unreadable", "backend_failures")


@dataclass
class FrameDecision:
    accepted: bool
    layer: str = ""
    reason: str = ""
    decides_trust: bool = False
    quarantine: bool = True        # False: count only (encrypted_without_backend "drop")
    header: PrimaryHeader = None
    spi: int = None
    frame: object = None           # TmFrame
    sa: object = None              # SaConfig
    protection: str = None
    data_field: bytes = None       # where packets come from (plaintext)
    verified: bool = False
    gap: bool = False              # the virtual channel frame count skipped
    warnings: list = field(default_factory=list)

    def link(self):
        """What the quarantine stores about the frame."""
        if self.header is None:
            return None
        return {"vcid": self.header.vcid, "spi": self.spi, "vc_count": self.header.vc_count,
                "mc_count": self.header.mc_count}


class FramePolicy:
    def __init__(self, replay):
        self.replay = replay
        self.vc_counts = {}    # vcid -> last accepted VC frame count
        self.mc_count = None
        self.counts = dict.fromkeys(COUNTERS, 0)

    def reset_counts(self):
        """A new connection: frame counts start over (the anti-replay counters do not)."""
        self.vc_counts = {}
        self.mc_count = None

    def check(self, raw, config, backend):
        self.counts["frames"] += 1
        decision = self._check(raw, config, backend)
        self.counts["accepted" if decision.accepted else "rejected"] += 1
        return decision

    def _check(self, raw, config, backend):
        if len(raw) != config.frame_length:
            return _reject("frame", f"frame is {len(raw)} bytes, expected {config.frame_length}")
        if config.has_fecf and not fecf_ok(raw):
            self.counts["fecf_errors"] += 1
            return _reject("frame", "FECF (CRC) does not match: the frame was corrupted in transit",
                           decides_trust=False)

        header = PrimaryHeader.from_bytes(raw)
        problem = _header_problem(header, config)
        if problem:
            return _reject("frame", problem, header=header)

        try:
            spi = read_spi(raw, header)
        except FrameError as error:
            return _reject(error.layer, error.reason, header=header)
        sa = config.sas.get(spi)
        if sa is None:
            return _reject("sdls", f"SPI {spi} is not a configured security association", header=header, spi=spi)
        allowed = config.vcs[header.vcid]
        if spi not in allowed:
            return _reject("sdls", f"SPI {spi} ({sa.mode}) is not allowed on virtual channel {header.vcid} "
                                   f"(allowed: {', '.join(map(str, sorted(allowed)))})", header=header, spi=spi)
        try:
            frame = parse_tm_frame(raw, header, sa, config.has_fecf)
        except FrameError as error:
            return _reject(error.layer, error.reason, header=header, spi=spi)

        usable = len(frame.data_field) - frame.pad_length
        if usable < 0:
            return _reject("sdls", f"pad length {frame.pad_length} is longer than the data field "
                                   f"({len(frame.data_field)} bytes)", header=header, spi=spi)
        if header.fhp not in (FHP_NO_PACKET_START, FHP_ONLY_IDLE) and header.fhp >= usable:
            return _reject("frame", f"first header pointer {header.fhp} is outside the {usable}-byte data field",
                           header=header, spi=spi)

        result = backend.process(frame, sa)
        decision = FrameDecision(accepted=True, header=header, spi=spi, frame=frame, sa=sa)
        if result.status == UNVERIFIED:
            self.counts["unverified"] += 1
            if config.unverified_auth == "deny":
                return _reject("sdls", f"SPI {spi}'s MAC is not checked (no crypto backend) and "
                                       "link.unverified_auth is deny", header=header, spi=spi, decides_trust=False)
        elif result.status == UNREADABLE:
            self.counts["unreadable"] += 1
            return _reject("sdls", result.detail, header=header, spi=spi, decides_trust=False,
                           quarantine=config.encrypted_without_backend == "deny")
        elif result.status == FAILED:
            self.counts["backend_failures"] += 1
            return _reject("sdls", f"SDLS check failed for SPI {spi}: {result.detail}", header=header, spi=spi)
        elif result.status == UNAVAILABLE:
            self.counts["backend_failures"] += 1
            return _reject("sdls", f"crypto backend unavailable: {result.detail}", header=header, spi=spi,
                           decides_trust=False)
        elif result.status not in (CLEAR, VERIFIED, DECRYPTED):
            return _reject("sdls", f"crypto backend returned unknown status {result.status!r}", header=header,
                           spi=spi, decides_trust=False)
        decision.verified = result.status in (VERIFIED, DECRYPTED)
        decision.protection = result.protection
        data = result.data_field
        decision.data_field = data[:len(data) - frame.pad_length] if frame.pad_length else data

        replay_problem = self.replay.check(sa, frame, config, verified=decision.verified)
        if replay_problem:
            self.counts["replay_rejections"] += 1
            self.replay.rejected += 1
            return _reject("sdls", replay_problem, header=header, spi=spi, decides_trust=False)

        if config.frame_counter_gap != "ignore":
            last = self.vc_counts.get(header.vcid)
            if last is not None:
                expected = (last + 1) % FRAME_COUNT_MODULO
                if header.vc_count != expected:
                    self.counts["vc_count_gaps"] += 1
                    text = (f"virtual channel {header.vcid} frame count {header.vc_count}, expected {expected} "
                            f"(frames lost, injected or repeated)")
                    if config.frame_counter_gap == "deny":
                        return _reject("frame", text, header=header, spi=spi, decides_trust=False)
                    decision.gap = True
                    decision.warnings.append(text)
            if self.mc_count is not None and header.mc_count != (self.mc_count + 1) % FRAME_COUNT_MODULO:
                self.counts["mc_count_gaps"] += 1
        return decision

    def commit(self, decision):
        """Record an accepted frame."""
        header = decision.header
        self.vc_counts[header.vcid] = header.vc_count
        self.mc_count = header.mc_count
        self.replay.commit(decision.sa, decision.frame)


def _header_problem(header, config):
    if header.version != 0:
        return f"transfer frame version {header.version}, expected 0 (TM)"
    if header.scid != config.scid:
        return f"spacecraft ID {header.scid}, expected {config.scid}"
    if header.vcid not in config.vcs:
        return (f"virtual channel {header.vcid} is not configured "
                f"(configured: {', '.join(map(str, sorted(config.vcs)))})")
    if header.ocf_flag != config.has_ocf:
        return f"OCF flag {header.ocf_flag}, expected {int(config.has_ocf)}"
    if header.sec_hdr_flag != config.secondary_header:
        return f"secondary header flag {header.sec_hdr_flag}, expected {int(config.secondary_header)}"
    if header.sync_flag or header.order_flag or header.seg_len_id != 3:
        return (f"not in packet mode (sync flag {header.sync_flag}, packet order flag {header.order_flag}, "
                f"segment length ID {header.seg_len_id}; expected 0, 0, 3)")
    return None


def _reject(layer, reason, header=None, spi=None, decides_trust=True, quarantine=True):
    return FrameDecision(accepted=False, layer=layer, reason=reason, decides_trust=decides_trust,
                         quarantine=quarantine, header=header, spi=spi)
