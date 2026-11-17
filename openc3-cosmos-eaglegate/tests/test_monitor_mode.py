"""Monitor mode (decision C12 in EagleGate/DECISIONS.md): try rules without
losing telemetry. settings.enforcement "monitor" delivers every packet the
rules would deny; a rule's "monitor": true only records its denials. Either way
the would-be denial is quarantined (not releasable) and counted."""
import pytest
from conftest import ccsds, hk_status, rules_json, status_3
from eaglegate_release import ReleaseError, check_entry
from eaglegate_rules_error import RulesError
from eaglegate_rules_parser import parse_rules
from test_firewall_protocol import apids, build, read_all

ALLOW_HK = {"id": "allow-hk", "action": "ALLOW", "match": {"apid": [2]}}
SEQ = {"id": "seq-hk", "type": "sequence", "action": "DENY", "match": {"apid": [2]}, "params": {}}


def monitored(**settings):
    return rules_json([ALLOW_HK], settings={"enforcement": "monitor", **settings})


def test_monitor_mode_delivers_and_records(valkey, log):
    iface, fw, _ = build([hk_status() + status_3() + ccsds(0x100)], rules=monitored())
    assert apids(read_all(iface)) == [2, 3, 0x100]  # nothing withheld
    assert (fw.rejected, fw.monitored) == (0, 2)
    assert not fw.connection_untrusted
    [first, _] = valkey.stream("QUARANTINE__EAGLEGATE_INT")
    assert first["monitor"] == "true" and first["releasable"] == "false"
    assert first["reason"].startswith("WOULD DENY (monitor) by default action")
    items = fw.status_items()
    assert (items["MONITORED"], items["ENFORCEMENT"], items["REJECTED"]) == (2, "MONITOR", 0)
    assert any("delivered APID 0x003 that it would deny" in m[1] for m in log)


def test_a_first_packet_that_would_be_denied_does_not_untrust_in_monitor_mode():
    iface, fw, _ = build([status_3() + hk_status()], rules=monitored())
    assert apids(read_all(iface)) == [3, 2]
    assert not fw.connection_untrusted


def test_the_structural_check_still_applies_in_monitor_mode():
    iface, fw, _ = build([ccsds(2, version=3) + hk_status()], rules=monitored())
    read_all(iface)
    assert fw.rejected == 1 and fw.rejected_by_stage["STRUCTURAL"] == 1


def test_a_monitored_rule_records_and_the_rules_below_decide(valkey):
    rules = rules_json([{**SEQ, "monitor": True}, ALLOW_HK])
    iface, fw, _ = build([hk_status(seq=1) + hk_status(seq=5) + status_3()], rules=rules)
    assert apids(read_all(iface)) == [2, 2]  # seq 5 jumps, but the rule is only monitored
    assert (fw.monitored, fw.rejected) == (1, 1)  # APID 3 is still denied by default
    [entry] = [e for e in valkey.stream("QUARANTINE__EAGLEGATE_INT") if e["monitor"] == "true"]
    assert entry["rule_id"] == "seq-hk" and "WOULD DENY (monitor) by rule 'seq-hk'" in entry["reason"]
    assert fw.status_items()["ENFORCEMENT"] == "ENFORCE" and fw.status_items()["MONITOR_RULES"] == 1
    assert fw.ruleset.summary()["monitor_rules"] == ["seq-hk"]


def test_a_monitored_stateful_rule_learns_as_if_it_had_denied():
    """Monitor must show what enforce would do: a packet the monitored sequence
    rule flags does not move its last count, exactly like an enforced denial."""
    rules = rules_json([{**SEQ, "monitor": True}, ALLOW_HK])
    iface, fw, _ = build([hk_status(seq=1) + hk_status(seq=5) + hk_status(seq=2)], rules=rules)
    read_all(iface)
    assert fw.monitored == 1  # seq 2 follows 1: fine, as under enforce
    rule = fw.ruleset.rules[0]
    assert rule.last_count[2] == 2


def test_monitor_entries_are_never_releasable(valkey):
    iface, _, _ = build([hk_status() + status_3()], rules=monitored())
    read_all(iface)
    [entry] = valkey.stream("QUARANTINE__EAGLEGATE_INT")
    fields = {k: (v.encode() if isinstance(v, str) else v) for k, v in entry.items()}
    with pytest.raises(ReleaseError, match="delivered already"):
        check_entry(fields, "1-0", "EAGLEGATE_INT", entry["sha256"])


def test_recent_rejections_flag_monitor_entries(valkey):
    import json

    iface, fw, _ = build([hk_status() + status_3()], rules=monitored())
    read_all(iface)
    fw._publish_status_if_due(force=True)
    [row] = json.loads(valkey.recent[-1]["RECENT_JSON"])
    assert row["monitor"] is True and row["reason"].startswith("WOULD DENY")


@pytest.mark.parametrize("rule, message", [
    ({**ALLOW_HK, "monitor": True}, "monitor only applies to DENY rules"),
    ({**SEQ, "monitor": "yes"}, "monitor must be true or false"),
])
def test_bad_monitor_flags_are_refused(rule, message):
    with pytest.raises(RulesError, match=message):
        parse_rules(rules_json([rule]))


def test_bad_enforcement_is_refused():
    with pytest.raises(RulesError, match="enforcement must be one of"):
        parse_rules(rules_json([], settings={"enforcement": "off"}))
