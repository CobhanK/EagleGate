"""The check rule types: range, sequence, rate, authenticity and text.

Each one can only DENY, and each documents its tunable "params" in its
docstring. The plain "match" rule and the Rule base class are in eaglegate_rule.py.
"""
import hashlib
import hmac
import math
import os
import re
import struct
from dataclasses import dataclass, field

from eaglegate_ccsds_header import CCSDS_HEADER_BYTES, MAX_PACKET, SEQ_COUNT_MODULO
from eaglegate_rule import Rule
from eaglegate_rules_error import RulesError
from eaglegate_text import (ENCODINGS, FORMULA_START, MAX_SUBSTRING, MAX_SUBSTRINGS, PADDINGS, TEXT_PROFILES,
                            TextCheck, floor_problem)
from eaglegate_validate import no_unknown_keys, require, to_int, to_number


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
    PARAM_SCHEMA = {
        "offset": {"type": "int", "min": 0, "max": MAX_PACKET - 1, "required": True,
                   "help": "byte offset of the value in the whole packet"},
        "data_type": {"type": "enum", "values": list(DATA_TYPES), "required": True,
                      "help": "always big-endian (CCSDS)"},
        "min": {"type": "number", "help": "lowest allowed value, inclusive"},
        "max": {"type": "number", "help": "highest allowed value, inclusive"},
    }
    PARAM_RULES = ["at least one of min and max", "min <= max"]

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
            # value missing: the packet is malformed for this APID
            return f"packet is {len(packet)} bytes, too short for {self.data_type} at offset {self.offset}"
        (value,) = struct.unpack_from(layout, packet, self.offset)
        if self.min <= value <= self.max:  # NaN fails both comparisons, so it fires
            return None
        return f"{self.data_type} at offset {self.offset} = {value}, allowed {_limits(self.min, self.max)}"


def _limits(low, high):
    if low == -math.inf:
        return f"<= {high:g}"
    if high == math.inf:
        return f">= {low:g}"
    return f"{low:g}..{high:g}"


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
    APID after a CHANGED rules file is applied sets the starting point. Reconnecting
    or re-applying the same file keeps the counts (so a dropped link cannot be used
    to replay a packet); after the spacecraft resets its counters, bump the rules
    "version" and apply the file to start fresh.
    """

    TYPE = "sequence"
    PARAM_KEYS = frozenset({"max_gap"})
    PARAM_SCHEMA = {
        "max_gap": {"type": "int", "min": 1, "max": SEQ_COUNT_MODULO // 2, "default": 1,
                    "help": "1 accepts only the next count; N also accepts a jump of up to N"},
    }

    max_gap: int = 1
    last_count: dict = field(default_factory=dict)  # APID -> count of the last allowed packet

    @classmethod
    def parse_params(cls, params, where):
        # Limited to half the count range, so "behind" and "ahead" stay distinguishable
        return {"max_gap": to_int(params.get("max_gap", 1), f"{where}.max_gap", 1, SEQ_COUNT_MODULO // 2)}

    def fires(self, header, packet, now):
        last = self.last_count.get(header.apid)
        if last is None:
            return None
        step = (header.seq_count - last) % SEQ_COUNT_MODULO  # how far ahead, allowing for wrap
        if 1 <= step <= self.max_gap:
            return None
        if step == 0:
            found = "repeats the last allowed count"
        elif step <= SEQ_COUNT_MODULO // 2:
            found = f"is {step} ahead"
        else:
            found = f"is {SEQ_COUNT_MODULO - step} behind"
        return (f"sequence count {header.seq_count} {found} (last allowed {last}, "
                f"max_gap {self.max_gap})")

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
    PARAM_SCHEMA = {
        "min_interval": {"type": "number", "min_exclusive": 0, "max": MAX_INTERVAL, "required": True,
                         "help": "seconds; set a little below the real cadence to allow jitter"},
    }

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
        if last is None or now - last >= self.min_interval:
            return None
        return f"{now - last:.3f} s after the last allowed packet, min_interval {self.min_interval:g} s"

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
    PARAM_SCHEMA = {
        "key_env": {"type": "string", "required": True,
                    "help": "NAME of the environment variable holding the hex key (never the key itself)"},
        "mac_bytes": {"type": "int", "min": 8, "max": 32, "default": 16, "help": "length of the MAC trailer"},
        "spi": {"type": "int", "min": 0, "max": 0xFFFF, "help": "required Security Parameter Index (optional)"},
    }

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
        """The reason shows the RECEIVED MAC (it was sent in the clear anyway) but
        never the expected one: that would hand out a valid MAC for this packet."""
        spi_bytes = SPI_BYTES if self.spi is not None else 0
        needed = CCSDS_HEADER_BYTES + spi_bytes + self.mac_bytes
        if len(packet) < needed:
            return f"packet is {len(packet)} bytes, too short for the security fields ({needed} bytes)"
        if self.spi is not None:
            spi_at = CCSDS_HEADER_BYTES
            spi = int.from_bytes(packet[spi_at:spi_at + SPI_BYTES], "big")
            if spi != self.spi:
                return f"SPI 0x{spi:04X}, expected 0x{self.spi:04X}"
        signed, mac = packet[:-self.mac_bytes], packet[-self.mac_bytes:]
        expected = hmac.new(self.key, signed, hashlib.sha256).digest()[:self.mac_bytes]
        if hmac.compare_digest(mac, expected):  # constant time, no timing leak
            return None
        return f"MAC mismatch, received {mac.hex()}"


# ---- text --------------------------------------------------------------------

MAX_TEXT_FIELDS = 32
FIELD_NAME = re.compile(r"[A-Za-z0-9_]{1,64}")
TEXT_ONLY = ("ascii", "utf8")


def _field_checks():
    return {
        "name": {"type": "string", "help": "shown in reasons, e.g. the item name in tlm.txt (letters, digits, _)"},
        "offset": {"type": "int", "min": 0, "max": MAX_PACKET - 1, "required": True,
                   "help": "byte offset of the field in the whole packet"},
        "length": {"type": "int", "min": 1, "max": MAX_PACKET, "required": True,
                   "help": "field size in bytes (the STRING item's bit size / 8)"},
    }


@dataclass(kw_only=True)
class TextRule(Rule):
    """Deny packets whose text fields contain characters they should not.

      "type": "text",
      "params": {
        "fields": [{"name": "ENG_SRCFILE", "offset": 80, "length": 64}],  # required
        "encoding": "ascii",       # ascii (default), utf8, or raw (binary: byte values)
        "profile": "safe_text",    # ascii/utf8: identifier, path, hex, numeric,
                                   #   printable, safe_text (default) or custom
        "also_allow": "",          # ascii/utf8: characters to add, e.g. "A-Z_ "
        "also_deny": "%;",         # ascii/utf8: characters to remove
        "allow_bytes": "0x20-0x7E", # raw: allowed byte values (empty: all)
        "deny_bytes": "0x1B",      # raw: byte values to refuse
        "deny_substrings": [".."], # text: literal, case-insensitive; raw: hex "1b5b"
        "padding": "nul",          # nul (default): trailing NULs, nothing after the
                                   #   first; space: trailing spaces; none
        "no_formula_start": true,  # ascii/utf8: refuse a first character of = + - @
        "min_length": 1, "max_length": 63   # bytes, after padding is removed
      }

    Control characters, DEL and (in ascii) every byte >= 0x80 can never be
    allowed in text; use encoding raw for binary fields. Profiles and syntax
    are in eaglegate_text.py. A packet too short for a field is denied.
    """

    TYPE = "text"
    PARAM_KEYS = frozenset({"fields", "encoding", "profile", "also_allow", "also_deny", "allow_bytes",
                            "deny_bytes", "deny_substrings", "padding", "no_formula_start",
                            "min_length", "max_length"})
    PARAM_SCHEMA = {
        "fields": {"type": "object_list", "required": True, "min_items": 1, "max_items": MAX_TEXT_FIELDS,
                   "fields": _field_checks(), "help": "the text fields to check, from the packet's STRING items"},
        "encoding": {"type": "enum", "values": list(ENCODINGS), "default": "ascii",
                     "value_help": {"ascii": "printable ASCII only (most flight software)",
                                    "utf8": "ASCII rules plus safe non-ASCII characters",
                                    "raw": "binary data: allow or deny byte values"}},
        "profile": {"type": "enum", "values": list(TEXT_PROFILES), "default": "safe_text", "encodings": list(TEXT_ONLY),
                    "value_help": {name: p["description"] for name, p in TEXT_PROFILES.items()}},
        "also_allow": {"type": "charset", "encodings": list(TEXT_ONLY),
                       "help": 'characters to add to the profile, e.g. "A-Z_ " (- is literal at the start or end)'},
        "also_deny": {"type": "charset", "encodings": list(TEXT_ONLY),
                      "help": "characters to remove from the profile"},
        "allow_bytes": {"type": "byte_set", "encodings": ["raw"],
                        "help": "allowed byte values, e.g. 0x20-0x7E, 0x0A (empty: every byte)"},
        "deny_bytes": {"type": "byte_set", "encodings": ["raw"], "help": "byte values to refuse, e.g. 0x1B, 0x7F"},
        "deny_substrings": {"type": "string_list", "max_items": MAX_SUBSTRINGS,
                            "help": "text: literal, case-insensitive; raw: hex like 1b5b"},
        "padding": {"type": "enum", "values": list(PADDINGS), "default": "nul",
                    "value_help": {"nul": "trailing NULs; nothing may follow the first NUL",
                                   "space": "trailing spaces", "none": "the whole field is text"}},
        "no_formula_start": {"type": "bool", "default": True, "encodings": list(TEXT_ONLY),
                             "help": f"refuse a first character of {' '.join(FORMULA_START)} (CSV formula injection)"},
        "min_length": {"type": "int", "min": 0, "max": MAX_PACKET, "help": "bytes, after padding is removed"},
        "max_length": {"type": "int", "min": 0, "max": MAX_PACKET, "help": "bytes, after padding is removed"},
    }
    PARAM_RULES = ["min_length <= max_length", "profile custom needs also_allow",
                   "settings marked ascii/utf8 or raw apply only to that encoding"]
    # Starting points for the rules editor's "Add rule" menu
    PRESETS = [
        {"name": name, "title": f"Text: {TEXT_PROFILES[profile]['title'].lower()}{suffix}",
         "params": {"fields": [{"name": "FIELD", "offset": 12, "length": 32}], "encoding": "ascii",
                    "profile": profile, "padding": "nul", "no_formula_start": True, **extra}}
        for name, profile, suffix, extra in [
            ("text-identifier", "identifier", " (names, modes, IDs)", {"min_length": 1}),
            ("text-path", "path", " (no ..)", {"deny_substrings": [".."], "min_length": 1}),
            ("text-safe", "safe_text", " (scripts, CSV, SQL)", {}),
            ("text-printable", "printable", " (display only)", {}),
            ("text-hex", "hex", "", {"min_length": 1}),
            ("text-numeric", "numeric", "", {"min_length": 1}),
        ]
    ] + [
        {"name": "text-utf8", "title": "Text: UTF-8 safe text (non-English)",
         "params": {"fields": [{"name": "FIELD", "offset": 12, "length": 32}], "encoding": "utf8",
                    "profile": "safe_text", "padding": "nul", "no_formula_start": True}},
        {"name": "raw-7bit", "title": "Raw bytes: 7-bit values only (0x00-0x7F)",
         "params": {"fields": [{"name": "FIELD", "offset": 12, "length": 32}], "encoding": "raw",
                    "allow_bytes": "0x00-0x7F", "padding": "none"}},
    ]

    text_fields: list   # [(label, offset, length)]
    check: TextCheck

    @classmethod
    def parse_params(cls, params, where):
        encoding = params.get("encoding", "ascii")
        require(encoding in ENCODINGS, f"{where}.encoding must be one of {list(ENCODINGS)}, got {encoding!r}")
        for key, spec in cls.PARAM_SCHEMA.items():
            if key in params and "encodings" in spec and encoding not in spec["encodings"]:
                raise RulesError(f"{where}.{key} does not apply to encoding {encoding} "
                                 f"(only {', '.join(spec['encodings'])})")
        fields = _parse_fields(params.get("fields"), f"{where}.fields")
        settings = {"encoding": encoding, "where": where}

        padding = params.get("padding", "nul")
        require(padding in PADDINGS, f"{where}.padding must be one of {list(PADDINGS)}, got {padding!r}")
        settings["padding"] = padding
        for key in ("min_length", "max_length"):
            if key in params:
                settings[key] = to_int(params[key], f"{where}.{key}", 0, MAX_PACKET)
        if "min_length" in settings and "max_length" in settings:
            require(settings["min_length"] <= settings["max_length"], f"{where} min_length > max_length")

        substrings = params.get("deny_substrings", [])
        require(isinstance(substrings, list) and len(substrings) <= MAX_SUBSTRINGS,
                f"{where}.deny_substrings must be a list of at most {MAX_SUBSTRINGS} strings")
        for index, text in enumerate(substrings):
            _check_substring(text, encoding, f"{where}.deny_substrings[{index}]")
        settings["deny_substrings"] = list(substrings)

        if encoding == "raw":
            for key in ("allow_bytes", "deny_bytes"):
                settings[key] = params.get(key, "")
        else:
            profile = params.get("profile", "safe_text")
            require(profile in TEXT_PROFILES, f"{where}.profile must be one of {list(TEXT_PROFILES)}, got {profile!r}")
            if profile == "custom":
                require(params.get("also_allow"), f"{where}: profile custom needs also_allow")
            no_formula = params.get("no_formula_start", True)
            require(isinstance(no_formula, bool), f"{where}.no_formula_start must be true or false")
            settings.update(profile=profile, also_allow=params.get("also_allow", ""),
                            also_deny=params.get("also_deny", ""), no_formula_start=no_formula)
        return {"text_fields": fields, "check": TextCheck(**settings)}  # TextCheck validates the sets

    def fires(self, header, packet, now):
        for label, offset, length in self.text_fields:
            if offset + length > len(packet):
                return f"field {label}: packet is {len(packet)} bytes, too short for {length} bytes at offset {offset}"
            detail = self.check.check(packet[offset:offset + length])
            if detail:
                return f"field {label} (packet offset {offset}): {detail}"
        return None


def _parse_fields(raw, where):
    require(isinstance(raw, list) and 1 <= len(raw) <= MAX_TEXT_FIELDS,
            f"{where} must be a list of 1 to {MAX_TEXT_FIELDS} fields")
    fields = []
    for index, field_spec in enumerate(raw):
        at = f"{where}[{index}]"
        require(isinstance(field_spec, dict), f"{at} must be an object")
        no_unknown_keys(field_spec, {"name", "offset", "length"}, at)
        require("offset" in field_spec and "length" in field_spec, f"{at} needs 'offset' and 'length'")
        offset = to_int(field_spec["offset"], f"{at}.offset", 0, MAX_PACKET - 1)
        length = to_int(field_spec["length"], f"{at}.length", 1, MAX_PACKET)
        require(offset + length <= MAX_PACKET, f"{at} ends past the largest CCSDS packet")
        name = field_spec.get("name", f"#{index + 1}")
        require(isinstance(name, str) and (FIELD_NAME.fullmatch(name) or name == f"#{index + 1}"),
                f"{at}.name may only use letters, digits and _ (up to 64)")
        fields.append((name, offset, length))
    return fields


def _check_substring(text, encoding, where):
    require(isinstance(text, str) and 0 < len(text) <= MAX_SUBSTRING,
            f"{where} must be a non-empty string of at most {MAX_SUBSTRING} characters")
    if encoding == "raw":
        try:
            require(len(bytes.fromhex(text)) > 0, f"{where} must hold at least one byte")
        except ValueError:
            raise RulesError(f"{where} must be hex for encoding raw, like 1b5b") from None
        return
    for ch in text:
        cp = ord(ch)
        if encoding == "ascii" and not 0x20 <= cp <= 0x7E:
            raise RulesError(f"{where}: U+{cp:04X} is not printable ASCII")
        if floor_problem(cp):
            raise RulesError(f"{where}: U+{cp:04X} is a {floor_problem(cp)}")
