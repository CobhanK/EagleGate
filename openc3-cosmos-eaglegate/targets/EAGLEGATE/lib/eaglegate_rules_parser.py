"""Turn the text of firewall_rules.json into a Ruleset, or raise RulesError.

Validation is strict: in a firewall, a silently ignored typo can mean
"match everything". Every unknown key or bad value is an error.

Rules file format (JSON):
{
  "version": 3,                       # required int, bump on every change
  "description": "...",               # optional
  "default_action": "DENY",           # required: ALLOW or DENY when no rule fires
  "rules": [                          # checked top to bottom, FIRST RULE THAT FIRES WINS
    {
      "id": "allow-housekeeping",     # required, unique
      "type": "match",                # optional, default "match"; see RULE_TYPES below
      "action": "ALLOW",              # required: ALLOW or DENY (check types: DENY only)
      "enabled": true,                # optional, default true
      "description": "...",           # optional
      "match": {                      # required; which packets the rule applies to.
        "apid": [2, "0x003"],               # ALL listed conditions must hold
        "apid_range": ["0x100", "0x1FF"],   # inclusive
        "packet_type": "TLM",               # TLM or CMD
        "sec_hdr": true,                    # secondary header flag
        "min_length": 7,                    # total packet bytes, inclusive
        "max_length": 512,
        "bytes": [{"offset": 6, "mask": "0x80", "value": "0x80"}]  # (data[offset] & mask) == value
      },
      "params": { ... }               # tunable settings of the rule type, documented
    }                                 # at the top of each eaglegate_rule_<type>.py
  ]
}
Integers may be JSON numbers or strings like "0x1FF".

Put check rules (range, sequence, rate, authenticity) ABOVE the ALLOW rules
for the same packets, or the ALLOW decides first and the check never runs.
"""
import hashlib
import json

from eaglegate_match import Match
from eaglegate_rule import MatchRule
from eaglegate_rule_authenticity import AuthenticityRule
from eaglegate_rule_range import RangeRule
from eaglegate_rule_rate import RateRule
from eaglegate_rule_sequence import SequenceRule
from eaglegate_rules_error import RulesError
from eaglegate_ruleset import Ruleset
from eaglegate_validate import no_unknown_keys, require

RULE_TYPES = {cls.TYPE: cls for cls in (MatchRule, RangeRule, SequenceRule, RateRule, AuthenticityRule)}
ACTIONS = ("ALLOW", "DENY")
TOP_LEVEL_KEYS = {"version", "description", "default_action", "rules"}
RULE_KEYS = {"id", "type", "action", "enabled", "description", "match", "params"}
MAX_RULES = 500          # bounds the work done per packet


def parse_rules(text):
    """Validate rules text (str or bytes) and return a Ruleset."""
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as error:
        raise RulesError(f"not valid JSON: {error}") from None

    require(isinstance(doc, dict), "top level must be a JSON object")
    no_unknown_keys(doc, TOP_LEVEL_KEYS, "top level")
    version = doc.get("version")
    require(isinstance(version, int) and not isinstance(version, bool) and version >= 0,
            "'version' must be a non-negative integer")
    default_action = _action(doc.get("default_action"), ACTIONS, "'default_action'")
    raw_rules = doc.get("rules")
    require(isinstance(raw_rules, list), "'rules' must be a list")
    require(len(raw_rules) <= MAX_RULES, f"too many rules ({len(raw_rules)} > {MAX_RULES})")

    rules = []
    seen_ids = set()
    for index, raw in enumerate(raw_rules):
        rule_id, rule = _parse_rule(raw, f"rules[{index}]")
        require(rule_id not in seen_ids, f"duplicate rule '{rule_id}'")
        seen_ids.add(rule_id)
        if rule is not None:
            rules.append(rule)

    return Ruleset(version=version, default_action=default_action, rules=rules, sha256=sha256)


def _parse_rule(raw, where):
    """Return (rule_id, Rule) for one entry of the "rules" list; Rule is None if disabled.
    A disabled rule's param VALUES are not checked (so, for example, a disabled
    authenticity rule does not need its key); everything else is."""
    require(isinstance(raw, dict), f"{where} must be an object")
    no_unknown_keys(raw, RULE_KEYS, where)
    rule_id = raw.get("id")
    require(isinstance(rule_id, str) and rule_id.strip(), f"{where}.id must be a non-empty string")
    where = f"rule '{rule_id}'"

    rule_type = raw.get("type", "match")
    require(rule_type in RULE_TYPES, f"{where}.type must be one of {list(RULE_TYPES)}, got {rule_type!r}")
    rule_class = RULE_TYPES[rule_type]
    action = _action(raw.get("action"), rule_class.ACTIONS, f"{where}.action")

    enabled = raw.get("enabled", True)
    require(isinstance(enabled, bool), f"{where}.enabled must be true or false")
    require("match" in raw, f"{where} is missing 'match' (use {{}} to match everything)")
    match = Match.parse(raw["match"], f"{where}.match")

    params = raw.get("params", {})
    require(isinstance(params, dict), f"{where}.params must be an object")
    no_unknown_keys(params, rule_class.PARAM_KEYS, f"{where}.params")
    if not enabled:
        return rule_id, None

    settings = rule_class.parse_params(params, f"{where}.params")
    return rule_id, rule_class(id=rule_id, action=action, match=match, **settings)


def _action(value, allowed, where):
    require(value in allowed, f"{where} must be one of {list(allowed)}, got {value!r}")
    return value
