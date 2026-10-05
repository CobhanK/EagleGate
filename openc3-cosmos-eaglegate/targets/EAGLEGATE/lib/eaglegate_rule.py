"""One firewall rule: an action plus the conditions a packet must meet."""
from dataclasses import dataclass, field


@dataclass
class Rule:
    """A rule matches a packet when EVERY condition that is set holds.
    A condition left as None (or an empty list) is not checked."""

    id: str
    action: str                  # "ALLOW" or "DENY"
    apids: frozenset = None      # APID must be one of these
    apid_min: int = None         # APID must be in apid_min..apid_max (inclusive)
    apid_max: int = None
    packet_type: int = None      # TLM (0) or CMD (1)
    sec_hdr: int = None          # 0 or 1
    min_length: int = None       # total packet bytes, inclusive
    max_length: int = None
    byte_checks: list = field(default_factory=list)  # (offset, mask, value) tuples
    hits: int = 0                # how many packets this rule has decided

    def matches(self, header, packet):
        if self.apids is not None and header.apid not in self.apids:
            return False
        if self.apid_min is not None and not (self.apid_min <= header.apid <= self.apid_max):
            return False
        if self.packet_type is not None and header.packet_type != self.packet_type:
            return False
        if self.sec_hdr is not None and header.sec_hdr != self.sec_hdr:
            return False
        if self.min_length is not None and len(packet) < self.min_length:
            return False
        if self.max_length is not None and len(packet) > self.max_length:
            return False
        for offset, mask, value in self.byte_checks:
            if offset >= len(packet):
                return False  # packet too short to have this byte
            if packet[offset] & mask != value:
                return False
        return True
