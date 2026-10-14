"""The "match" object every rule has: which packets the rule applies to."""
from dataclasses import dataclass, field
from functools import cached_property

from eaglegate_ccsds_header import CMD, MAX_APID, MAX_PACKET, MIN_PACKET, TLM
from eaglegate_validate import no_unknown_keys, require, to_int

MATCH_KEYS = {"apid", "apid_range", "packet_type", "sec_hdr", "min_length", "max_length", "bytes"}
BYTE_KEYS = {"offset", "mask", "value"}


@dataclass
class Match:
    """Holds for a packet when EVERY condition that is set holds.
    A condition left as None (or an empty list) is not checked, so an empty
    match ({} in the rules file) holds for every packet."""

    apids: frozenset = None      # APID must be one of these
    apid_min: int = None         # APID must be in apid_min..apid_max (inclusive)
    apid_max: int = None
    packet_type: int = None      # TLM (0) or CMD (1)
    sec_hdr: int = None          # 0 or 1
    min_length: int = None       # total packet bytes, inclusive
    max_length: int = None
    byte_checks: list = field(default_factory=list)  # (offset, mask, value) tuples

    def holds(self, header, packet):
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

    @cached_property
    def summary(self):
        """The conditions in words, e.g. "matched APID 0x002; length 11..11".
        Cached: a match rule returns it for every packet it decides."""
        parts = []
        if self.apids is not None:
            parts.append("APID " + ",".join(f"0x{apid:03X}" for apid in sorted(self.apids)))
        if self.apid_min is not None:
            parts.append(f"APID 0x{self.apid_min:03X}..0x{self.apid_max:03X}")
        if self.packet_type is not None:
            parts.append("type " + ("CMD" if self.packet_type == CMD else "TLM"))
        if self.sec_hdr is not None:
            parts.append(f"sec_hdr {bool(self.sec_hdr)}")
        if self.min_length is not None or self.max_length is not None:
            low = "" if self.min_length is None else self.min_length
            high = "" if self.max_length is None else self.max_length
            parts.append(f"length {low}..{high}")
        for offset, mask, value in self.byte_checks:
            parts.append(f"byte[{offset}] & 0x{mask:02X} == 0x{value:02X}")
        return "matched " + ("; ".join(parts) if parts else "every packet")

    @classmethod
    def parse(cls, raw, where):
        """Build a Match from a rule's "match" object."""
        require(isinstance(raw, dict), f"{where} must be an object")
        no_unknown_keys(raw, MATCH_KEYS, where)
        match = cls()

        if "apid" in raw:
            apids = raw["apid"]
            require(isinstance(apids, list) and apids, f"{where}.apid must be a non-empty list")
            match.apids = frozenset(to_int(apid, f"{where}.apid", 0, MAX_APID) for apid in apids)

        if "apid_range" in raw:
            apid_range = raw["apid_range"]
            require(isinstance(apid_range, list) and len(apid_range) == 2,
                    f"{where}.apid_range must be [low, high]")
            match.apid_min = to_int(apid_range[0], f"{where}.apid_range", 0, MAX_APID)
            match.apid_max = to_int(apid_range[1], f"{where}.apid_range", 0, MAX_APID)
            require(match.apid_min <= match.apid_max, f"{where}.apid_range low > high")

        if "packet_type" in raw:
            require(raw["packet_type"] in ("TLM", "CMD"), f"{where}.packet_type must be TLM or CMD")
            match.packet_type = TLM if raw["packet_type"] == "TLM" else CMD

        if "sec_hdr" in raw:
            require(isinstance(raw["sec_hdr"], bool), f"{where}.sec_hdr must be true or false")
            match.sec_hdr = int(raw["sec_hdr"])

        if "min_length" in raw:
            match.min_length = to_int(raw["min_length"], f"{where}.min_length", MIN_PACKET, MAX_PACKET)
        if "max_length" in raw:
            match.max_length = to_int(raw["max_length"], f"{where}.max_length", MIN_PACKET, MAX_PACKET)
        if match.min_length is not None and match.max_length is not None:
            require(match.min_length <= match.max_length, f"{where} min_length > max_length")

        if "bytes" in raw:
            checks = raw["bytes"]
            require(isinstance(checks, list) and checks, f"{where}.bytes must be a non-empty list")
            for index, check in enumerate(checks):
                match.byte_checks.append(_parse_byte_check(check, f"{where}.bytes[{index}]"))

        return match


def _parse_byte_check(check, where):
    """Return (offset, mask, value) for one entry of "bytes"."""
    require(isinstance(check, dict), f"{where} must be an object")
    no_unknown_keys(check, BYTE_KEYS, where)
    require("offset" in check and "value" in check, f"{where} needs 'offset' and 'value'")
    offset = to_int(check["offset"], f"{where}.offset", 0, MAX_PACKET - 1)
    mask = to_int(check.get("mask", 0xFF), f"{where}.mask", 0, 0xFF)
    value = to_int(check["value"], f"{where}.value", 0, 0xFF)
    require(value & ~mask == 0, f"{where}.value has bits outside mask (can never match)")
    return (offset, mask, value)
