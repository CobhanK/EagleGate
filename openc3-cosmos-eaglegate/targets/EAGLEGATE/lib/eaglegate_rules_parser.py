"""Turn the text of firewall_rules.json into a Ruleset, or raise RulesError.

Validation is strict: in a firewall, a silently ignored typo can mean
"match everything". Every unknown key or bad value is an error.

Rules file format (JSON):
{
  "version": 3,                       # required int, bump on every change
  "description": "...",               # optional
  "default_action": "DENY",           # required: ALLOW or DENY when nothing matches
  "rules": [                          # checked top to bottom, FIRST MATCH WINS
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

from eaglegate_ccsds_header import CMD, TLM
from eaglegate_rule import Rule
from eaglegate_rules_error import RulesError
from eaglegate_ruleset import Ruleset

ACTIONS = ("ALLOW", "DENY")
TOP_LEVEL_KEYS = {"version", "description", "default_action", "rules"}
RULE_KEYS = {"id", "action", "enabled", "description", "match"}
MATCH_KEYS = {"apid", "apid_range", "packet_type", "sec_hdr", "min_length", "max_length", "bytes"}
BYTE_KEYS = {"offset", "mask", "value"}
MAX_RULES = 500          # bounds the work done per packet
MAX_APID = 0x7FF
MIN_PACKET = 7           # 6-byte header + at least 1 payload byte
MAX_PACKET = 65542       # largest possible CCSDS space packet


def parse_rules(text):
    """Validate rules text (str or bytes) and return a Ruleset."""
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as error:
        raise RulesError(f"not valid JSON: {error}") from None

    _require(isinstance(doc, dict), "top level must be a JSON object")
    _no_unknown_keys(doc, TOP_LEVEL_KEYS, "top level")
    version = doc.get("version")
    _require(isinstance(version, int) and not isinstance(version, bool) and version >= 0,
             "'version' must be a non-negative integer")
    default_action = _action(doc.get("default_action"), "'default_action'")
    raw_rules = doc.get("rules")
    _require(isinstance(raw_rules, list), "'rules' must be a list")
    _require(len(raw_rules) <= MAX_RULES, f"too many rules ({len(raw_rules)} > {MAX_RULES})")

    rules = []
    seen_ids = set()
    for index, raw in enumerate(raw_rules):
        rule, enabled = _parse_rule(raw, f"rules[{index}]")
        _require(rule.id not in seen_ids, f"duplicate rule '{rule.id}'")
        seen_ids.add(rule.id)
        if enabled:
            rules.append(rule)

    return Ruleset(version=version, default_action=default_action, rules=rules, sha256=sha256)


def _parse_rule(raw, where):
    """Return (Rule, enabled) for one entry of the "rules" list."""
    _require(isinstance(raw, dict), f"{where} must be an object")
    _no_unknown_keys(raw, RULE_KEYS, where)
    rule_id = raw.get("id")
    _require(isinstance(rule_id, str) and rule_id.strip(), f"{where}.id must be a non-empty string")
    where = f"rule '{rule_id}'"
    rule = Rule(id=rule_id, action=_action(raw.get("action"), f"{where}.action"))
    enabled = raw.get("enabled", True)
    _require(isinstance(enabled, bool), f"{where}.enabled must be true or false")
    _require("match" in raw, f"{where} is missing 'match' (use {{}} to match everything)")
    _parse_match(raw["match"], rule, f"{where}.match")
    return rule, enabled


def _parse_match(match, rule, where):
    """Copy the conditions in a rule's "match" object onto the Rule."""
    _require(isinstance(match, dict), f"{where} must be an object")
    _no_unknown_keys(match, MATCH_KEYS, where)

    if "apid" in match:
        apids = match["apid"]
        _require(isinstance(apids, list) and apids, f"{where}.apid must be a non-empty list")
        rule.apids = frozenset(_int(apid, f"{where}.apid", 0, MAX_APID) for apid in apids)

    if "apid_range" in match:
        apid_range = match["apid_range"]
        _require(isinstance(apid_range, list) and len(apid_range) == 2,
                 f"{where}.apid_range must be [low, high]")
        rule.apid_min = _int(apid_range[0], f"{where}.apid_range", 0, MAX_APID)
        rule.apid_max = _int(apid_range[1], f"{where}.apid_range", 0, MAX_APID)
        _require(rule.apid_min <= rule.apid_max, f"{where}.apid_range low > high")

    if "packet_type" in match:
        _require(match["packet_type"] in ("TLM", "CMD"), f"{where}.packet_type must be TLM or CMD")
        rule.packet_type = TLM if match["packet_type"] == "TLM" else CMD

    if "sec_hdr" in match:
        _require(isinstance(match["sec_hdr"], bool), f"{where}.sec_hdr must be true or false")
        rule.sec_hdr = int(match["sec_hdr"])

    if "min_length" in match:
        rule.min_length = _int(match["min_length"], f"{where}.min_length", MIN_PACKET, MAX_PACKET)
    if "max_length" in match:
        rule.max_length = _int(match["max_length"], f"{where}.max_length", MIN_PACKET, MAX_PACKET)
    if rule.min_length is not None and rule.max_length is not None:
        _require(rule.min_length <= rule.max_length, f"{where} min_length > max_length")

    if "bytes" in match:
        checks = match["bytes"]
        _require(isinstance(checks, list) and checks, f"{where}.bytes must be a non-empty list")
        for index, check in enumerate(checks):
            rule.byte_checks.append(_parse_byte_check(check, f"{where}.bytes[{index}]"))


def _parse_byte_check(check, where):
    """Return (offset, mask, value) for one entry of "bytes"."""
    _require(isinstance(check, dict), f"{where} must be an object")
    _no_unknown_keys(check, BYTE_KEYS, where)
    _require("offset" in check and "value" in check, f"{where} needs 'offset' and 'value'")
    offset = _int(check["offset"], f"{where}.offset", 0, MAX_PACKET - 1)
    mask = _int(check.get("mask", 0xFF), f"{where}.mask", 0, 0xFF)
    value = _int(check["value"], f"{where}.value", 0, 0xFF)
    _require(value & ~mask == 0, f"{where}.value has bits outside mask (can never match)")
    return (offset, mask, value)


# ---- small validation helpers ----------------------------------------------

def _require(ok, message):
    if not ok:
        raise RulesError(message)


def _no_unknown_keys(obj, allowed, where):
    unknown = sorted(set(obj) - allowed)
    _require(not unknown, f"{where}: unknown key(s) {unknown}; allowed: {sorted(allowed)}")


def _action(value, where):
    _require(value in ACTIONS, f"{where} must be one of {list(ACTIONS)}, got {value!r}")
    return value


def _int(value, where, low, high):
    """Accept a JSON integer or a string like "0x1FF"; check it is in low..high."""
    if isinstance(value, bool):
        raise RulesError(f"{where}: expected an integer, got {value!r}")
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError:
            raise RulesError(f"{where}: {value!r} is not an integer") from None
    _require(isinstance(value, int), f"{where}: expected an integer, got {value!r}")
    _require(low <= value <= high, f"{where}: {value} out of range {low}..{high}")
    return value
