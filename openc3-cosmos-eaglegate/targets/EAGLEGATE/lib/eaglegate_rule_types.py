"""The check rule types: range, sequence, rate and authenticity.

Each one can only DENY, and each documents its tunable "params" in its
docstring. The plain "match" rule and the Rule base class are in eaglegate_rule.py.
"""
import hashlib
import hmac
import math
import os
import struct
from dataclasses import dataclass, field

from eaglegate_ccsds_header import CCSDS_HEADER_BYTES, MAX_PACKET, SEQ_COUNT_MODULO
from eaglegate_rule import Rule
from eaglegate_rules_error import RulesError
from eaglegate_validate import require, to_int, to_number


# ---- range -------------------------------------------------------------------

DATA_TYPES = {
    "UINT8": ">B", "INT8": ">b",
    "UINT16": ">H", "INT16": ">h",
    "UINT32": ">I", "INT32": ">i",
    "FLOAT32": ">f", "FLOAT64": ">d",
}


@dataclass(kw_only=True)
class RangeRule(Rule):
    """Deny packets carrying a physically impossible value.

      "type": "range",
      "params": {
        "offset": 12,            # byte offset of the value in the whole packet
        "data_type": "INT16",    # one of DATA_TYPES, always big-endian (CCSDS)
        "min": -40, "max": 85    # documented limits, inclusive; at least one is required
      }

    Take the limits from the NOS3 component configuration or the LIMITS lines in
    cmd_tlm/tlm.txt. A packet too short to contain the value is also denied.
    """

    TYPE = "range"
    PARAM_KEYS = frozenset({"offset", "data_type", "min", "max"})

    offset: int
    data_type: str
    min: float = -math.inf
    max: float = math.inf

    @classmethod
    def parse_params(cls, params, where):
        require("offset" in params and "data_type" in params, f"{where} needs 'offset' and 'data_type'")
        require(params["data_type"] in DATA_TYPES,
                f"{where}.data_type must be one of {list(DATA_TYPES)}, got {params['data_type']!r}")
        require("min" in params or "max" in params, f"{where} needs 'min', 'max' or both")
        low = to_number(params.get("min", -math.inf), f"{where}.min")
        high = to_number(params.get("max", math.inf), f"{where}.max")
        require(low <= high, f"{where} min > max")
        return {
            "offset": to_int(params["offset"], f"{where}.offset", 0, MAX_PACKET - 1),
            "data_type": params["data_type"],
            "min": low,
            "max": high,
        }

    def fires(self, header, packet, now):
        layout = DATA_TYPES[self.data_type]
        if self.offset + struct.calcsize(layout) > len(packet):
            return True  # value missing: the packet is malformed for this APID
        (value,) = struct.unpack_from(layout, packet, self.offset)
        return not (self.min <= value <= self.max)  # NaN fails both comparisons, so it fires


# ---- sequence ----------------------------------------------------------------

@dataclass(kw_only=True)
class SequenceRule(Rule):
    """Deny replayed, repeated or reordered packets.

      "type": "sequence",
      "params": {
        "max_gap": 1    # optional, default 1: only the very next count is accepted.
                        # N also accepts a jump of up to N, for links that lose packets.
      }

    Counts are tracked per APID and wrap from 16383 to 0. The first packet of each
    APID after the rules are (re)loaded sets the starting point, so reloading the
    rules is also how operators recover after the spacecraft resets its counters.
    """

    TYPE = "sequence"
    PARAM_KEYS = frozenset({"max_gap"})

    max_gap: int = 1
    last_count: dict = field(default_factory=dict)  # APID -> count of the last allowed packet

    @classmethod
    def parse_params(cls, params, where):
        # Limited to half the count range, so "behind" and "ahead" stay distinguishable
        return {"max_gap": to_int(params.get("max_gap", 1), f"{where}.max_gap", 1, SEQ_COUNT_MODULO // 2)}

    def fires(self, header, packet, now):
        last = self.last_count.get(header.apid)
        if last is None:
            return False
        step = (header.seq_count - last) % SEQ_COUNT_MODULO  # how far ahead, allowing for wrap
        return not (1 <= step <= self.max_gap)

    def record(self, header, now):
        self.last_count[header.apid] = header.seq_count


# ---- rate --------------------------------------------------------------------

MAX_INTERVAL = 86400  # one day; anything longer is almost certainly a typo


@dataclass(kw_only=True)
class RateRule(Rule):
    """Deny packets that arrive faster than the spacecraft's beacon cadence.

      "type": "rate",
      "params": {
        "min_interval": 0.9   # seconds; set a little below the real cadence to allow jitter
      }

    Tracked per APID. Only packets that arrive too EARLY can be filtered; a
    beacon that never arrives is a monitoring problem, not a firewall decision.
    """

    TYPE = "rate"
    PARAM_KEYS = frozenset({"min_interval"})

    min_interval: float
    last_time: dict = field(default_factory=dict)  # APID -> arrival time of the last allowed packet

    @classmethod
    def parse_params(cls, params, where):
        require("min_interval" in params, f"{where} needs 'min_interval' (seconds)")
        interval = to_number(params["min_interval"], f"{where}.min_interval")
        require(0 < interval <= MAX_INTERVAL, f"{where}.min_interval must be in 0..{MAX_INTERVAL} seconds")
        return {"min_interval": interval}

    def fires(self, header, packet, now):
        last = self.last_time.get(header.apid)
        return last is not None and now - last < self.min_interval

    def record(self, header, now):
        self.last_time[header.apid] = now


# ---- authenticity ------------------------------------------------------------

SPI_BYTES = 2
MIN_KEY_BYTES = 16


@dataclass(kw_only=True)
class AuthenticityRule(Rule):
    """Deny packets without a valid cryptographic signature.

      "type": "authenticity",
      "params": {
        "key_env": "EAGLEGATE_AUTH_KEY",  # environment variable holding the key as hex
        "mac_bytes": 16,                  # optional, default 16: length of the MAC trailer
        "spi": "0x0001"                   # optional: required Security Parameter Index
      }

    Packet layout, modelled on CCSDS SDLS (Space Data Link Security) authentication:

      [ primary header | SPI (2 bytes, if "spi" is set) | data ... | MAC ]

    MAC = the first mac_bytes of HMAC-SHA256(key, everything before the MAC). It
    covers the primary header too, so changing the sequence count breaks the MAC;
    pair this rule with a sequence rule to also stop exact replays.

    The key never goes in the rules file (operators read and edit it). Store it as
    a COSMOS secret and expose it to the interface with SECRET ENV in plugin.txt.
    """

    TYPE = "authenticity"
    PARAM_KEYS = frozenset({"key_env", "mac_bytes", "spi"})

    key: bytes = field(repr=False)  # repr=False keeps the key out of logs
    mac_bytes: int = 16
    spi: int = None

    @classmethod
    def parse_params(cls, params, where):
        key_env = params.get("key_env")
        require(isinstance(key_env, str) and key_env, f"{where}.key_env must name an environment variable")
        key_hex = os.environ.get(key_env)
        require(key_hex, f"{where}: environment variable {key_env} is not set")
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            raise RulesError(f"{where}: {key_env} must hold the key as hex") from None
        require(len(key) >= MIN_KEY_BYTES, f"{where}: key in {key_env} must be at least {MIN_KEY_BYTES} bytes")
        spi = params.get("spi")
        return {
            "key": key,
            "mac_bytes": to_int(params.get("mac_bytes", 16), f"{where}.mac_bytes", 8, 32),
            "spi": None if spi is None else to_int(spi, f"{where}.spi", 0, 0xFFFF),
        }

    def fires(self, header, packet, now):
        spi_bytes = SPI_BYTES if self.spi is not None else 0
        if len(packet) < CCSDS_HEADER_BYTES + spi_bytes + self.mac_bytes:
            return True  # too short to carry the security fields
        if self.spi is not None:
            spi_at = CCSDS_HEADER_BYTES
            if int.from_bytes(packet[spi_at:spi_at + SPI_BYTES], "big") != self.spi:
                return True
        signed, mac = packet[:-self.mac_bytes], packet[-self.mac_bytes:]
        expected = hmac.new(self.key, signed, hashlib.sha256).digest()[:self.mac_bytes]
        return not hmac.compare_digest(mac, expected)  # constant time, no timing leak
