"""Rules engine tests: pure Python, no COSMOS runtime at all."""
import pytest

from conftest import ccsds, rules_json, shipped_rules_text
from eaglegate_rules import RulesError, compile_ruleset


def evaluate(rules, packet, default_action="DENY"):
    return compile_ruleset(rules_json(rules, default_action)).evaluate(packet)


# ---- the shipped rules file ----

def test_shipped_rules_file_is_valid_and_matches_old_policy():
    rs = compile_ruleset(shipped_rules_text())
    assert rs.default_action == "DENY"
    assert [r.id for r in rs.rules] == ["deny-commands-on-tlm-link", "allow-housekeeping"]  # examples disabled
    assert rs.evaluate(ccsds(2))[0] == "ALLOW"
    assert rs.evaluate(ccsds(3))[0] == "ALLOW"
    assert rs.evaluate(ccsds(0x100)) == ("DENY", None)
    assert rs.evaluate(ccsds(2, packet_type=1)) == ("DENY", "deny-commands-on-tlm-link")


# ---- matching semantics ----

def test_first_match_wins():
    rules = [
        {"id": "deny-5", "action": "DENY", "match": {"apid": [5]}},
        {"id": "allow-all", "action": "ALLOW", "match": {}},
    ]
    assert evaluate(rules, ccsds(5)) == ("DENY", "deny-5")
    assert evaluate(rules, ccsds(6)) == ("ALLOW", "allow-all")


def test_all_conditions_in_a_rule_must_hold():
    rules = [{"id": "r", "action": "ALLOW",
              "match": {"apid_range": ["0x100", "0x1FF"], "max_length": 20, "sec_hdr": True}}]
    assert evaluate(rules, ccsds(0x150, b"\x00" * 10, sec_hdr=1))[0] == "ALLOW"
    assert evaluate(rules, ccsds(0x150, b"\x00" * 30, sec_hdr=1))[0] == "DENY"   # too long
    assert evaluate(rules, ccsds(0x150, b"\x00" * 10, sec_hdr=0))[0] == "DENY"   # no sec hdr
    assert evaluate(rules, ccsds(0x250, b"\x00" * 10, sec_hdr=1))[0] == "DENY"   # APID out of range


def test_default_action_allow():
    rules = [{"id": "deny-5", "action": "DENY", "match": {"apid": [5]}}]
    assert evaluate(rules, ccsds(9), default_action="ALLOW") == ("ALLOW", None)


def test_byte_mask_match_and_short_packet():
    rules = [{"id": "flag", "action": "DENY",
              "match": {"bytes": [{"offset": 6, "mask": "0x80", "value": "0x80"}]}}]
    assert evaluate(rules, ccsds(5, b"\x81"), "ALLOW") == ("DENY", "flag")
    assert evaluate(rules, ccsds(5, b"\x7f"), "ALLOW") == ("ALLOW", None)
    far = [{"id": "far", "action": "DENY", "match": {"bytes": [{"offset": 100, "value": 0}]}}]
    assert evaluate(far, ccsds(5, b"\x00"), "ALLOW") == ("ALLOW", None)  # too short -> no match


def test_disabled_rules_are_skipped():
    rules = [{"id": "off", "action": "DENY", "enabled": False, "match": {}}]
    assert evaluate(rules, ccsds(1), "ALLOW") == ("ALLOW", None)


def test_hit_counters():
    rs = compile_ruleset(rules_json([{"id": "a", "action": "ALLOW", "match": {"apid": [1]}}]))
    for apid in (1, 1, 2):
        rs.evaluate(ccsds(apid))
    assert rs.summary()["rule_hits"] == {"a": 2}
    assert rs.summary()["default_hits"] == 1


def test_sha_identifies_exact_content():
    a = compile_ruleset(rules_json([], version=1))
    b = compile_ruleset(rules_json([], version=1))
    c = compile_ruleset(rules_json([], version=2))
    assert a.sha256 == b.sha256 != c.sha256


# ---- strict validation: every mistake is an error, never a silent match-all ----

@pytest.mark.parametrize("text, message", [
    ("{not json", "not valid JSON"),
    ('{"version": 1, "default_action": "DENY", "rules": [], "extra": 1}', "unknown key"),
    ('{"version": -1, "default_action": "DENY", "rules": []}', "version"),
    ('{"version": true, "default_action": "DENY", "rules": []}', "version"),
    ('{"version": 1, "default_action": "BLOCK", "rules": []}', "default_action"),
    ('{"version": 1, "default_action": "DENY"}', "'rules' must be a list"),
])
def test_top_level_errors(text, message):
    with pytest.raises(RulesError, match=message):
        compile_ruleset(text)


@pytest.mark.parametrize("rule, message", [
    ({"action": "DENY", "match": {}}, "id must be"),
    ({"id": "r", "action": "deny", "match": {}}, "action must be one of"),
    ({"id": "r", "action": "DENY"}, "missing 'match'"),
    ({"id": "r", "action": "DENY", "match": {"apids": [5]}}, r"unknown key\(s\) \['apids'\]"),  # typo!
    ({"id": "r", "action": "DENY", "match": {"apid": []}}, "non-empty list"),
    ({"id": "r", "action": "DENY", "match": {"apid": [0x800]}}, "out of range"),
    ({"id": "r", "action": "DENY", "match": {"apid": ["0xZZ"]}}, "not an integer"),
    ({"id": "r", "action": "DENY", "match": {"apid_range": [9, 3]}}, "low > high"),
    ({"id": "r", "action": "DENY", "match": {"packet_type": "TM"}}, "TLM or CMD"),
    ({"id": "r", "action": "DENY", "match": {"min_length": 50, "max_length": 10}}, "min_length > max_length"),
    ({"id": "r", "action": "DENY", "match": {"bytes": [{"offset": 1, "mask": "0x0F", "value": "0xF0"}]}},
     "outside mask"),
    ({"id": "r", "action": "DENY", "enabled": "yes", "match": {}}, "enabled must be"),
])
def test_rule_errors(rule, message):
    with pytest.raises(RulesError, match=message):
        compile_ruleset(rules_json([rule]))


def test_duplicate_ids_rejected():
    rule = {"id": "same", "action": "DENY", "match": {}}
    with pytest.raises(RulesError, match="duplicate"):
        compile_ruleset(rules_json([rule, rule]))


def test_error_messages_name_the_rule():
    rules = [{"id": "ok", "action": "ALLOW", "match": {}},
             {"id": "broken-one", "action": "ALLOW", "match": {"apid": [99999]}}]
    with pytest.raises(RulesError, match="rule 'broken-one'"):
        compile_ruleset(rules_json(rules))
