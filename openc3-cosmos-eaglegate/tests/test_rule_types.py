"""Tests for the check rule types: range, sequence, rate and authenticity."""
import hashlib
import hmac
import struct

import pytest

from conftest import ccsds, rules_json
from eaglegate_rules_error import RulesError
from eaglegate_rules_parser import parse_rules

KEY_HEX = "00112233445566778899aabbccddeeff"
ALLOW_ALL = {"id": "allow-all", "action": "ALLOW", "match": {}}


def ruleset(check):
    """One check rule above an allow-everything rule: the check is the only filter."""
    return parse_rules(rules_json([check, ALLOW_ALL]))


def check(rule_type, params, match=None):
    return {"id": rule_type, "type": rule_type, "action": "DENY",
            "match": match or {}, "params": params}


# ---- range ----

def test_range_denies_values_outside_limits():
    rs = ruleset(check("range", {"offset": 6, "data_type": "INT16", "min": -40, "max": 85}))
    assert rs.evaluate(ccsds(2, struct.pack(">h", 20)))[0] == "ALLOW"
    assert rs.evaluate(ccsds(2, struct.pack(">h", -40)))[0] == "ALLOW"   # limits are inclusive
    assert rs.evaluate(ccsds(2, struct.pack(">h", 86))) == ("DENY", "range")
    assert rs.evaluate(ccsds(2, struct.pack(">h", -41))) == ("DENY", "range")


def test_range_denies_nan_and_missing_value():
    rs = ruleset(check("range", {"offset": 6, "data_type": "FLOAT32", "max": 100}))
    assert rs.evaluate(ccsds(2, struct.pack(">f", 1.5)))[0] == "ALLOW"
    assert rs.evaluate(ccsds(2, struct.pack(">f", float("nan"))))[0] == "DENY"
    assert rs.evaluate(ccsds(2, b"\x00\x00"))[0] == "DENY"  # too short for a FLOAT32


def test_range_only_checks_packets_it_matches():
    rs = ruleset(check("range", {"offset": 6, "data_type": "UINT8", "max": 10}, {"apid": [2]}))
    assert rs.evaluate(ccsds(2, b"\xff"))[0] == "DENY"
    assert rs.evaluate(ccsds(3, b"\xff"))[0] == "ALLOW"


# ---- sequence ----

def test_sequence_accepts_next_and_denies_replay():
    rs = ruleset(check("sequence", {}))
    assert rs.evaluate(ccsds(2, seq=10))[0] == "ALLOW"   # first packet sets the baseline
    assert rs.evaluate(ccsds(2, seq=11))[0] == "ALLOW"
    assert rs.evaluate(ccsds(2, seq=11)) == ("DENY", "sequence")  # replay
    assert rs.evaluate(ccsds(2, seq=5)) == ("DENY", "sequence")   # old packet
    assert rs.evaluate(ccsds(2, seq=13)) == ("DENY", "sequence")  # gap, max_gap is 1
    assert rs.evaluate(ccsds(2, seq=12))[0] == "ALLOW"


def test_sequence_wraps_and_tracks_each_apid():
    rs = ruleset(check("sequence", {"max_gap": 3}))
    assert rs.evaluate(ccsds(2, seq=16383))[0] == "ALLOW"
    assert rs.evaluate(ccsds(2, seq=1))[0] == "ALLOW"    # wrapped, gap of 2
    assert rs.evaluate(ccsds(3, seq=500))[0] == "ALLOW"  # separate counter per APID


def test_sequence_ignores_packets_denied_by_a_later_rule():
    """A forged packet with the next count must not use up that count."""
    rules = [check("sequence", {}),
             {"id": "deny-flag", "action": "DENY", "match": {"bytes": [{"offset": 6, "value": 1}]}},
             ALLOW_ALL]
    rs = parse_rules(rules_json(rules))
    assert rs.evaluate(ccsds(2, b"\x00", seq=1))[0] == "ALLOW"
    assert rs.evaluate(ccsds(2, b"\x01", seq=2)) == ("DENY", "deny-flag")  # forged
    assert rs.evaluate(ccsds(2, b"\x00", seq=2))[0] == "ALLOW"             # real one still fine


# ---- rate ----

def test_rate_denies_packets_faster_than_cadence():
    rs = ruleset(check("rate", {"min_interval": 0.9}))
    assert rs.evaluate(ccsds(2), now=100.0)[0] == "ALLOW"
    assert rs.evaluate(ccsds(2), now=100.5) == ("DENY", "rate")
    assert rs.evaluate(ccsds(3), now=100.5)[0] == "ALLOW"  # separate per APID
    assert rs.evaluate(ccsds(2), now=101.0)[0] == "ALLOW"  # measured from last ALLOWED packet


# ---- authenticity ----

def signed(apid, data, key_hex=KEY_HEX, mac_bytes=16, spi=None):
    payload = (spi.to_bytes(2, "big") if spi is not None else b"") + data
    unsigned = ccsds(apid, payload + b"\x00" * mac_bytes)[:-mac_bytes]  # header covers the MAC too
    mac = hmac.new(bytes.fromhex(key_hex), unsigned, hashlib.sha256).digest()[:mac_bytes]
    return unsigned + mac


@pytest.fixture
def auth_key(monkeypatch):
    monkeypatch.setenv("TEST_AUTH_KEY", KEY_HEX)


def test_authenticity_accepts_valid_and_denies_tampered(auth_key):
    rs = ruleset(check("authenticity", {"key_env": "TEST_AUTH_KEY"}))
    good = signed(2, b"hello")
    assert rs.evaluate(good)[0] == "ALLOW"
    tampered = good[:7] + b"X" + good[8:]
    assert rs.evaluate(tampered) == ("DENY", "authenticity")
    assert rs.evaluate(signed(2, b"hello", key_hex="ff" * 16))[0] == "DENY"  # wrong key
    assert rs.evaluate(ccsds(2, b"short"))[0] == "DENY"                     # no MAC at all


def test_authenticity_checks_spi(auth_key):
    rs = ruleset(check("authenticity", {"key_env": "TEST_AUTH_KEY", "spi": 1, "mac_bytes": 8}))
    assert rs.evaluate(signed(2, b"data", mac_bytes=8, spi=1))[0] == "ALLOW"
    assert rs.evaluate(signed(2, b"data", mac_bytes=8, spi=2))[0] == "DENY"


def test_authenticity_key_never_in_repr(auth_key):
    rs = ruleset(check("authenticity", {"key_env": "TEST_AUTH_KEY"}))
    assert KEY_HEX not in repr(rs) and "\\x00\\x11" not in repr(rs)


# ---- validation ----

@pytest.mark.parametrize("rule, message", [
    ({"id": "r", "type": "firewall", "action": "DENY", "match": {}}, "type must be one of"),
    (check("sequence", {}) | {"action": "ALLOW"}, r"action must be one of \['DENY'\]"),
    (check("sequence", {"max_gaps": 2}), r"unknown key\(s\) \['max_gaps'\]"),
    (check("sequence", {"max_gap": 0}), "out of range"),
    (check("range", {"offset": 6, "data_type": "INT12", "max": 1}), "data_type must be one of"),
    (check("range", {"offset": 6, "data_type": "INT16"}), "needs 'min', 'max' or both"),
    (check("range", {"offset": 6, "data_type": "INT16", "min": 5, "max": 1}), "min > max"),
    (check("range", {"offset": 6, "data_type": "INT16", "max": "10"}), "expected a number"),
    (check("rate", {}), "needs 'min_interval'"),
    (check("rate", {"min_interval": 0}), "min_interval must be"),
    (check("authenticity", {"key_env": "NOT_SET_ANYWHERE"}), "is not set"),
    ({"id": "r", "action": "ALLOW", "match": {}, "params": {"x": 1}}, r"unknown key\(s\) \['x'\]"),
])
def test_rule_type_errors(rule, message):
    with pytest.raises(RulesError, match=message):
        parse_rules(rules_json([rule]))


def test_bad_key_value_is_reported_without_the_key(monkeypatch):
    monkeypatch.setenv("TEST_AUTH_KEY", "abcd")  # too short
    with pytest.raises(RulesError, match="at least 16 bytes") as error:
        parse_rules(rules_json([check("authenticity", {"key_env": "TEST_AUTH_KEY"})]))
    assert "abcd" not in str(error.value)


def test_disabled_rule_does_not_need_its_key():
    rule = check("authenticity", {"key_env": "NOT_SET_ANYWHERE"}) | {"enabled": False}
    assert parse_rules(rules_json([rule])).rules == []
