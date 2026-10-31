"""The text rule: allowlists for text fields in telemetry."""
import json
import os
import timeit

import pytest

from conftest import ROOT, RULES_PATH, ccsds, hk_status, rules_json
from eaglegate_rules_error import RulesError
from eaglegate_rules_parser import RULE_TYPES, parse_rules
from eaglegate_rule_types import TextRule
from eaglegate_text import TextCheck
from test_firewall_protocol import apids, build, read_all

CASES_FILE = os.path.join(ROOT, "tests", "fixtures", "text_rule_cases.json")
with open(CASES_FILE, encoding="utf-8") as f:
    CASES = json.load(f)["cases"]

APID = 0x0B1  # CF_TRANSPACKET in NOS3
FIELD = {"name": "ENG_SRCFILE", "offset": 6, "length": 16}


def text_rules(params, allow_after=True):
    rules = [{"id": "text-check", "type": "text", "action": "DENY", "match": {"apid": [APID]},
              "params": {"fields": [FIELD], **params}}]
    if allow_after:
        rules.append({"id": "allow", "action": "ALLOW", "match": {"apid": [2, APID]}})
    return rules_json(rules)


def packet(text, field_length=16):
    body = text if isinstance(text, bytes) else text.encode("utf-8")
    return ccsds(APID, body.ljust(field_length, b"\x00"))


def decide(params, text):
    verdict = parse_rules(text_rules(params)).evaluate(packet(text), now=0.0)
    return verdict.action, verdict.detail


# ---- the shared cases (also run against textCheck.js by `pnpm test`) ----

@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_shared_field_cases(case):
    assert TextCheck(**case["params"]).check(bytes.fromhex(case["field_hex"])) == case["expect"]


# ---- the rule ----

def test_allowed_text_passes_to_the_allow_rule():
    assert decide({"profile": "path"}, "/cf/data.bin") == ("ALLOW", "matched APID 0x002,0x0B1")


def test_reason_names_field_and_packet_offset():
    action, detail = decide({"profile": "path"}, "/cf/a\x1b[2J")
    assert action == "DENY"
    assert detail == "field ENG_SRCFILE (packet offset 6): byte 0x1B (ESC) at offset 5 is not allowed by profile path"


def test_every_field_is_checked():
    params = {"fields": [FIELD, {"name": "ENG_DSTFILE", "offset": 22, "length": 8}], "profile": "identifier"}
    rules = rules_json([{"id": "t", "type": "text", "action": "DENY", "match": {}, "params": params}])
    verdict = parse_rules(rules).evaluate(ccsds(APID, b"OK".ljust(16, b"\0") + b"bad;".ljust(8, b"\0")), now=0)
    assert verdict.rule_id == "t" and verdict.detail.startswith("field ENG_DSTFILE (packet offset 22)")


def test_unnamed_fields_are_numbered():
    params = {"fields": [{"offset": 6, "length": 4}], "profile": "identifier"}
    rules = rules_json([{"id": "t", "type": "text", "action": "DENY", "match": {}, "params": params}])
    assert parse_rules(rules).evaluate(ccsds(APID, b"a b\0"), now=0).detail.startswith("field #1 ")


def test_packet_too_short_for_the_field_is_denied():
    verdict = parse_rules(text_rules({})).evaluate(ccsds(APID, b"short"), now=0)
    assert verdict.detail == "field ENG_SRCFILE: packet is 11 bytes, too short for 16 bytes at offset 6"


def test_other_apids_are_not_checked():
    rules = rules_json([{"id": "t", "type": "text", "action": "DENY", "match": {"apid": [APID]},
                         "params": {"fields": [FIELD], "profile": "hex"}},
                        {"id": "allow", "action": "ALLOW", "match": {}}])
    assert parse_rules(rules).evaluate(hk_status(), now=0).rule_id == "allow"


def test_defaults_are_ascii_safe_text_nul_padding_no_formula():
    rule = parse_rules(text_rules({})).rules[0]
    assert (rule.check.encoding, rule.check.profile, rule.check.padding) == ("ascii", "safe_text", "nul")
    assert decide({}, "=1+2")[0] == "DENY" and decide({}, "a;b")[0] == "DENY"


# ---- reasons never carry the field's content ----

ATTACK = "=cmd|' /C calc'!A0"


def test_attack_bytes_never_reach_the_reason_quarantine_or_status(valkey):
    iface, proto, store = build(connect=False)
    iface.chunks = [hk_status(), packet(ATTACK, 32)]
    store.original = rules_json([
        {"id": "allow-hk", "action": "ALLOW", "match": {"apid": [2]}},
        {"id": "text-check", "type": "text", "action": "DENY", "match": {"apid": [APID]},
         "params": {"fields": [{"name": "MSG", "offset": 6, "length": 32}], "profile": "printable"}},
    ])
    iface.connect()
    assert apids(read_all(iface)) == [2]
    [entry] = [e for e in valkey.stream("__EAGLEGATE__QUARANTINE__EAGLEGATE_INT")]
    assert entry["rule_id"] == "text-check" and "spreadsheets treat as a formula" in entry["reason"]
    proto._publish_status_if_due(force=True)
    for text in (entry["reason"], entry["detail"], valkey.status[-1]["LAST_REASON"], proto.last_rejection["reason"]):
        assert "cmd|" not in text and "calc" not in text
    assert entry["bytes"][6:].startswith(ATTACK.encode())  # the evidence itself is kept, as bytes


def test_reason_for_terminal_escape_is_hex_not_the_byte():
    detail = decide({"profile": "printable"}, "a\x1b]52;c;ZXZpbA==\x07")[1]
    assert "\x1b" not in detail and "\x07" not in detail and "0x1B (ESC)" in detail


# ---- strict settings ----

@pytest.mark.parametrize("params, message", [
    ({"encoding": "ebcdic"}, "encoding must be one of"),
    ({"encoding": "raw", "profile": "path"}, "profile does not apply to encoding raw"),
    ({"encoding": "ascii", "allow_bytes": "0x00-0x7F"}, "allow_bytes does not apply to encoding ascii"),
    ({"encoding": "raw", "no_formula_start": True}, "no_formula_start does not apply"),
    ({"profile": "sql"}, "profile must be one of"),
    ({"profile": "custom"}, "profile custom needs also_allow"),
    ({"also_allow": "\t"}, "not printable ASCII"),
    ({"also_allow": "é"}, "not printable ASCII"),
    ({"encoding": "utf8", "also_allow": "‮"}, "can never be allowed"),
    ({"also_allow": "z-a"}, "is backwards"),
    ({"encoding": "raw", "allow_bytes": "0x00-0x1FF"}, "within 0x00-0xFF"),
    ({"encoding": "raw", "deny_bytes": "ESC"}, "not a byte value"),
    ({"encoding": "raw", "deny_substrings": ["1b5"]}, "must be hex"),
    ({"deny_substrings": [""]}, "non-empty string"),
    ({"deny_substrings": ["a"] * 21}, "at most 20"),
    ({"deny_substrings": ["\x1b"]}, "not printable ASCII"),
    ({"padding": "zero"}, "padding must be one of"),
    ({"no_formula_start": "yes"}, "must be true or false"),
    ({"min_length": 5, "max_length": 2}, "min_length > max_length"),
    ({"fields": []}, "list of 1 to 32 fields"),
    ({"fields": [{"offset": 6}]}, "needs 'offset' and 'length'"),
    ({"fields": [{"offset": 6, "length": 0}]}, "out of range"),
    ({"fields": [{"offset": 65540, "length": 16}]}, "ends past the largest CCSDS packet"),
    ({"fields": [{"name": "bad name;", "offset": 6, "length": 4}]}, "may only use letters"),
    ({"fields": [{"offset": 6, "length": 4, "size": 4}]}, "unknown key"),
    ({"surprise": 1}, "unknown key"),
])
def test_bad_settings_are_rules_errors(params, message):
    with pytest.raises(RulesError, match=message):
        parse_rules(text_rules(params))


def test_text_rules_can_only_deny():
    rules = rules_json([{"id": "t", "type": "text", "action": "ALLOW", "match": {}, "params": {"fields": [FIELD]}}])
    with pytest.raises(RulesError, match="must be one of \\['DENY'\\]"):
        parse_rules(rules)


# ---- presets and shipped examples ----

@pytest.mark.parametrize("preset", TextRule.PRESETS, ids=[p["name"] for p in TextRule.PRESETS])
def test_every_preset_is_a_valid_rule(preset):
    rules = rules_json([{"id": preset["name"], "type": "text", "action": "DENY", "match": {},
                         "params": preset["params"]}])
    assert parse_rules(rules).rules[0].TYPE == "text"


def test_shipped_text_examples_are_valid_when_enabled():
    with open(RULES_PATH) as f:
        doc = json.load(f)
    examples = [r for r in doc["rules"] if r.get("type") == "text"]
    assert len(examples) >= 3
    for rule in examples:
        rule["enabled"] = True
    assert len(parse_rules(json.dumps({**doc, "rules": examples})).rules) == len(examples)


def test_text_rule_is_registered():
    assert RULE_TYPES["text"] is TextRule


# ---- cost ----

def test_five_cfdp_sized_fields_stay_cheap():
    """The five 64-byte file names of CF_TRANSPACKET: a few microseconds per packet."""
    fields = [{"name": f"F{i}", "offset": 6 + 64 * i, "length": 64} for i in range(5)]
    rule = parse_rules(rules_json([{"id": "t", "type": "text", "action": "DENY", "match": {},
                                    "params": {"fields": fields, "profile": "path"}}])).rules[0]
    pkt = ccsds(APID, b"".join(b"/cf/downlink/file_0001.bin".ljust(64, b"\0") for _ in range(5)))
    assert rule.fires(None, pkt, 0) is None
    per_packet = timeit.timeit(lambda: rule.fires(None, pkt, 0), number=2000) / 2000
    assert per_packet < 100e-6  # generous for slow CI; typically a few microseconds
