"""Traffic counts: every packet the firewall judges, allowed or not.

The rejection counters say what was refused; these say what the link carried,
so an operator can tell a quiet link from a blocked one, see which APIDs are
arriving, and spot lost packets. They are the core's half of the Link status
tab on the EagleGate Firewall page (extensions such as eaglegate-sdls add
their own frame counts there).

  * totals: packets judged, allowed, rejected, and their bytes
  * per APID: the same, the last sequence count, when it was last seen, and
    sequence gaps
  * a sequence gap is a packet whose 14-bit sequence count is not the previous
    one + 1 (mod 16384) for its APID: packets lost or rejected upstream, a
    sender restart, or injected/reordered packets. Informational only: rules
    (the "sequence" rule type) decide what to do about it. Continuity starts
    over on each new connection.

Only framed packets are counted here. Bytes dropped without framing (bad
headers, untrusted connections) are the firewall's DISCARDED_BYTES. APIDs are
11 bits, so the per-APID table holds at most 2048 entries whatever arrives.
"""
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from eaglegate_ccsds_header import CCSDS_HEADER_BYTES, SEQ_COUNT_MODULO, CcsdsHeader
from eaglegate_quarantine import utc_now


@dataclass
class ApidCounts:
    packets: int = 0
    allowed: int = 0
    rejected: int = 0
    bytes: int = 0
    seq_gaps: int = 0
    seq_missing: int = 0          # packets the gaps skipped over (an estimate)
    last_seq: int = None          # None at the start of a connection
    last_time: float = None       # time.time() of the last packet

    def describe(self):
        return {"packets": self.packets, "allowed": self.allowed, "rejected": self.rejected,
                "bytes": self.bytes, "seq_gaps": self.seq_gaps, "seq_missing": self.seq_missing,
                "last_seq": self.last_seq, "last_time": _time_text(self.last_time)}


class TrafficCounter:
    def __init__(self, clock=time.time):
        self.clock = clock
        self.packets = 0
        self.allowed = 0
        self.rejected = 0
        self.bytes = 0
        self.bytes_allowed = 0
        self.seq_gaps = 0
        self.seq_missing = 0
        self.last_packet_time = None
        self.since = utc_now()
        self.apids = {}           # apid -> ApidCounts

    def record(self, data, allowed):
        """Count one judged packet. Never raises: counting must not change a decision."""
        now = self.clock()
        self.packets += 1
        self.bytes += len(data)
        self.last_packet_time = now
        if allowed:
            self.allowed += 1
            self.bytes_allowed += len(data)
        else:
            self.rejected += 1
        if len(data) < CCSDS_HEADER_BYTES:
            return
        header = CcsdsHeader.from_bytes(data)
        counts = self.apids.get(header.apid)
        if counts is None:
            counts = self.apids[header.apid] = ApidCounts()
        counts.packets += 1
        counts.bytes += len(data)
        counts.last_time = now
        if allowed:
            counts.allowed += 1
        else:
            counts.rejected += 1
        if counts.last_seq is not None:
            skipped = (header.seq_count - counts.last_seq - 1) % SEQ_COUNT_MODULO
            if skipped:
                counts.seq_gaps += 1
                counts.seq_missing += skipped
                self.seq_gaps += 1
                self.seq_missing += skipped
        counts.last_seq = header.seq_count

    def new_connection(self):
        """Sequence continuity is not expected across connections."""
        for counts in self.apids.values():
            counts.last_seq = None

    def describe(self):
        return {
            "since": self.since,
            "packets": self.packets,
            "allowed": self.allowed,
            "rejected": self.rejected,
            "bytes": self.bytes,
            "bytes_allowed": self.bytes_allowed,
            "seq_gaps": self.seq_gaps,
            "seq_missing": self.seq_missing,
            "last_packet_time": _time_text(self.last_packet_time),
            "apids": {f"0x{apid:03X}": counts.describe() for apid, counts in sorted(self.apids.items())},
        }


def _time_text(seconds):
    if seconds is None:
        return None
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")  # like utc_now()
