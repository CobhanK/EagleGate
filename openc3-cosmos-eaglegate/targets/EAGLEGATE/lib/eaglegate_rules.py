"""EAGLEGATE firewall rules engine.

Example Rules file format (JSON):
{
  "version": 3,                       # required int, bump on every change
  "description": "...",               # optional
  "default_action": "DENY",           # required: ALLOW or DENY when nothing matches
  "rules": [                          # evaluated top to bottom, FIRST MATCH WINS
    {
      "id": "allow-housekeeping",     # required, unique
      "action": "ALLOW",              # required: ALLOW or DENY
      "enabled": true,                # optional, default true
      "description": "...",           # optional
      "match": {                      # required; ALL listed conditions must hold
        "apid": [2, "0x003"],               # APID in list
        "apid_range": ["0x100", "0x1FF"],   # inclusive
        "packet_type": "TLM",               # TLM or CMD
        "sec_hdr": true,                    # secondary header flag
        "min_length": 7,                    # total packet bytes, inclusive
        "max_length": 512,
        "bytes": [{"offset": 6, "mask": "0x80", "value": "0x80"}]  # (data[offset] & mask) == value
      }
    }
  ]
}
Integers may be JSON numbers or strings like "0x1FF".
"""
import hashlib
import json
from dataclasses import dataclass, field

ACTIONS = ("ALLOW", "DENY")
TOP_LEVEL_KEYS = {"version", "description", "default_action", "rules"}
RULE_KEYS = {"id", "action", "enabled", "description", "match"}
MATCH_KEYS = {"apid", "apid_range", "packet_type", "sec_hdr", "min_length", "max_length", "bytes"}
BYTE_KEYS = {"offset", "mask", "value"}
MAX_RULES = 500          # bounds per-packet cost
MAX_APID = 0x7FF
MAX_PACKET = 65542       # largest possible CCSDS space packet


class RulesError(ValueError):
    """Raised for any invalid rules file. Message says exactly what and where."""


@dataclass(frozen=True)
class Header:
    version: int
    packet_type: int  # 0 = TLM, 1 = CMD
    sec_hdr: int
    apid: int
    total_length: int


def parse_header(data):
    """Parse a CCSDS primary header from at least 6 bytes."""
    return Header(
        version=data[0] >> 5,
        packet_type=(data[0] >> 4) & 0x1,
        sec_hdr=(data[0] >> 3) & 0x1,
        apid=((data[0] & 0x07) << 8) | data[1],
        total_length=((data[4] << 8) | data[5]) + 7,
    )


@dataclass
class Rule:
    id: str
    action: str
    conditions: list  # of callables (header, data) -> bool
    hits: int = 0


@dataclass
class Ruleset:
    version: int
    default_action: str
    rules: list
    sha256: str
    description: str = ""
    default_hits: int = field(default=0)

    def evaluate(self, data):
        """Return (action, rule_id) for one framed packet. rule_id None = default."""
        header = parse_header(data)
        for rule in self.rules:
            if all(cond(header, data) for cond in rule.conditions):
                rule.hits += 1
                return rule.action, rule.id
        self.default_hits += 1
        return self.default_action, None

    def summary(self):
        return {
            "version": self.version,
            "sha256": self.sha256,
            "default_action": self.default_action,
            "rule_count": len(self.rules),
            "rule_hits": {r.id: r.hits for r in self.rules},
            "default_hits": self.default_hits,
        }


def deny_all(reason):
    """Fail-closed ruleset used when no valid rules have ever been loaded."""
    return Ruleset(version=-1, default_action="DENY", rules=[], sha256="", description=reason)


# ---- compilation -----------------------------------------------------------

def compile_ruleset(text):
    """Validate rules text (str or bytes) and return a Ruleset. Raises RulesError."""
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise RulesError(f"not valid JSON: {e}") from None

    _require(isinstance(doc, dict), "top level must be a JSON object")
    _no_unknown(doc, TOP_LEVEL_KEYS, "top level")
    version = doc.get("version")
    _require(isinstance(version, int) and not isinstance(version, bool) and version >= 0,
             "'version' must be a non-negative integer")
    default_action = _action(doc.get("default_action"), "'default_action'")
    rules_in = doc.get("rules")
    _require(isinstance(rules_in, list), "'rules' must be a list")
    _require(len(rules_in) <= MAX_RULES, f"too many rules ({len(rules_in)} > {MAX_RULES})")

    rules, seen = [], set()
    for index, raw in enumerate(rules_in):
        where = f"rules[{index}]"
        _require(isinstance(raw, dict), f"{where} must be an object")
        _no_unknown(raw, RULE_KEYS, where)
        rule_id = raw.get("id")
        _require(isinstance(rule_id, str) and rule_id.strip(), f"{where}.id must be a non-empty string")
        where = f"rule '{rule_id}'"
        _require(rule_id not in seen, f"duplicate {where}")
        seen.add(rule_id)
        action = _action(raw.get("action"), f"{where}.action")
        enabled = raw.get("enabled", True)
        _require(isinstance(enabled, bool), f"{where}.enabled must be true or false")
        _require("match" in raw, f"{where} is missing 'match' (use {{}} to match everything)")
        conditions = _compile_match(raw["match"], where)
        if enabled:
            rules.append(Rule(rule_id, action, conditions))

    return Ruleset(version, default_action, rules, sha, doc.get("description", ""))


def _compile_match(match, where):
    _require(isinstance(match, dict), f"{where}.match must be an object")
    _no_unknown(match, MATCH_KEYS, f"{where}.match")
    conds = []

    if "apid" in match:
        apids = match["apid"]
        _require(isinstance(apids, list) and apids, f"{where}.match.apid must be a non-empty list")
        allowed = frozenset(_int(a, f"{where}.match.apid", 0, MAX_APID) for a in apids)
        conds.append(lambda h, d, s=allowed: h.apid in s)

    if "apid_range" in match:
        rng = match["apid_range"]
        _require(isinstance(rng, list) and len(rng) == 2, f"{where}.match.apid_range must be [low, high]")
        lo = _int(rng[0], f"{where}.match.apid_range", 0, MAX_APID)
        hi = _int(rng[1], f"{where}.match.apid_range", 0, MAX_APID)
        _require(lo <= hi, f"{where}.match.apid_range low > high")
        conds.append(lambda h, d, lo=lo, hi=hi: lo <= h.apid <= hi)

    if "packet_type" in match:
        ptype = match["packet_type"]
        _require(ptype in ("TLM", "CMD"), f"{where}.match.packet_type must be TLM or CMD")
        value = 0 if ptype == "TLM" else 1
        conds.append(lambda h, d, v=value: h.packet_type == v)

    if "sec_hdr" in match:
        flag = match["sec_hdr"]
        _require(isinstance(flag, bool), f"{where}.match.sec_hdr must be true or false")
        conds.append(lambda h, d, v=int(flag): h.sec_hdr == v)

    lo = _int(match["min_length"], f"{where}.match.min_length", 7, MAX_PACKET) if "min_length" in match else None
    hi = _int(match["max_length"], f"{where}.match.max_length", 7, MAX_PACKET) if "max_length" in match else None
    if lo is not None and hi is not None:
        _require(lo <= hi, f"{where}.match min_length > max_length")
    if lo is not None:
        conds.append(lambda h, d, v=lo: len(d) >= v)
    if hi is not None:
        conds.append(lambda h, d, v=hi: len(d) <= v)

    if "bytes" in match:
        checks = match["bytes"]
        _require(isinstance(checks, list) and checks, f"{where}.match.bytes must be a non-empty list")
        for i, chk in enumerate(checks):
            w = f"{where}.match.bytes[{i}]"
            _require(isinstance(chk, dict), f"{w} must be an object")
            _no_unknown(chk, BYTE_KEYS, w)
            _require("offset" in chk and "value" in chk, f"{w} needs 'offset' and 'value'")
            off = _int(chk["offset"], f"{w}.offset", 0, MAX_PACKET - 1)
            mask = _int(chk.get("mask", 0xFF), f"{w}.mask", 0, 0xFF)
            val = _int(chk["value"], f"{w}.value", 0, 0xFF)
            _require(val & ~mask == 0, f"{w}.value has bits outside mask (can never match)")
            # Packet too short for the offset -> condition is false (rule doesn't match)
            conds.append(lambda h, d, o=off, m=mask, v=val: len(d) > o and (d[o] & m) == v)

    return conds


# ---- helpers ---------------------------------------------------------------

def _require(ok, message):
    if not ok:
        raise RulesError(message)


def _no_unknown(obj, allowed, where):
    unknown = sorted(set(obj) - allowed)
    _require(not unknown, f"{where}: unknown key(s) {unknown}; allowed: {sorted(allowed)}")


def _action(value, where):
    _require(value in ACTIONS, f"{where} must be one of {list(ACTIONS)}, got {value!r}")
    return value


def _int(value, where, lo, hi):
    if isinstance(value, bool):
        raise RulesError(f"{where}: expected an integer, got {value!r}")
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError:
            raise RulesError(f"{where}: {value!r} is not an integer") from None
    _require(isinstance(value, int), f"{where}: expected an integer, got {value!r}")
    _require(lo <= value <= hi, f"{where}: {value} out of range {lo}..{hi}")
    return value
