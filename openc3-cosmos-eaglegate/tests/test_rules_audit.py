"""Rule changes in the audit stream (decision C13): every apply and every load
that changes the running rules is recorded with versions, hashes, what changed
and, from the EagleGate page, the change request's reason."""
import json

from conftest import rules_json
from eaglegate_rules_audit import rules_changes, summary
from eaglegate_test_support import admin_request
from test_firewall_protocol import build

V1 = rules_json([{"id": "allow-hk", "action": "ALLOW", "match": {"apid": [2]}},
                 {"id": "deny-3", "action": "DENY", "match": {"apid": [3]}}], version=1)
V2 = rules_json([{"id": "deny-3", "action": "DENY", "match": {"apid": [3, 4]}},
                 {"id": "allow-hk", "action": "ALLOW", "match": {"apid": [2]}, "enabled": False},
                 {"id": "seq", "type": "sequence", "action": "DENY", "match": {}, "params": {}, "monitor": True}],
                version=2, settings={"enforcement": "monitor"})


def sha(text):
    import hashlib

    return hashlib.sha256(text.encode()).hexdigest()


def test_changes_between_two_rule_files():
    changes = rules_changes(V1, V2)
    assert changes["added"] == ["seq"] and changes["removed"] == []
    assert changes["changed"] == ["deny-3", "allow-hk"]
    assert changes["disabled"] == ["allow-hk"] and changes["monitored"] == ["seq"]
    assert changes["reordered"] is True and changes["settings"] == ["enforcement"]
    text = summary(changes)
    assert "added seq" in text and "disabled allow-hk" in text and "settings enforcement" in text
    assert summary(rules_changes(V1, V1)) == "no rule changes (same rules, new version)"
    assert rules_changes(None, V1)["added"] == ["allow-hk", "deny-3"]  # from the built-in deny-all
    assert rules_changes("not json", V1)["added"] == ["allow-hk", "deny-3"]


def test_the_first_load_is_audited_once(valkey):
    iface, _, _ = build(rules=V1)
    [load] = valkey.audit("LOAD_RULES")
    assert (load["ok"], load["version"], load["previous_version"], load["source"]) == ("true", 1, -1, "original")
    assert "loaded the original rules" in load["detail"]
    iface.disconnect()
    iface.connect()  # same rules: nothing new to record
    assert len(valkey.audit("LOAD_RULES")) == 1


def test_an_apply_from_the_page_records_the_reason_and_changes(valkey):
    _, fw, store = build(rules=V1)
    store.pending = V2
    request, request_sha = admin_request(kind="reload_rules", reason="tighten APID 3 and 4",
                                         requested_by="alice", params={"pending_sha256": sha(V2)})
    store.requests["reload_rules"] = request
    assert fw.protocol_cmd("RELOAD_RULES", sha(V1), sha(V2), request_sha) is True
    assert fw.ruleset.version == 2
    [audit] = valkey.audit("RELOAD_RULES")
    assert (audit["ok"], audit["reason"], audit["requested_by"]) == ("true", "tighten APID 3 and 4", "alice")
    assert (audit["version"], audit["previous_version"], audit["sha256"]) == (2, 1, sha(V2))
    assert audit["enforcement"] == "monitor"
    assert json.loads(audit["changes"])["added"] == ["seq"]
    assert "applied new rules: version 1 -> 2" in audit["detail"] and "added seq" in audit["detail"]
    assert "reload_rules" not in store.requests  # consumed


def test_a_change_request_for_another_file_is_refused(valkey):
    _, fw, store = build(rules=V1)
    store.pending = V2
    request, request_sha = admin_request(kind="reload_rules", params={"pending_sha256": "0" * 64})
    store.requests["reload_rules"] = request
    fw.protocol_cmd("RELOAD_RULES", sha(V1), sha(V2), request_sha)
    assert fw.ruleset.version == 1
    [audit] = valkey.audit("RELOAD_RULES")
    assert audit["ok"] == "false" and "different rules file" in audit["detail"]
    assert "change request refused" in fw.rules_error


def test_applies_without_a_request_still_work_and_are_audited(valkey):
    """The apply_firewall_rules procedure sends no change request."""
    _, fw, store = build(rules=V1)
    store.pending = V2
    fw.protocol_cmd("RELOAD_RULES", sha(V1), sha(V2))
    [audit] = valkey.audit("RELOAD_RULES")
    assert audit["ok"] == "true" and "reason" not in audit  # no change request: no reason to record
    assert fw.ruleset.version == 2


def test_refused_rules_are_audited(valkey):
    _, fw, store = build(rules=V1)
    store.pending = "{ not json"
    fw.protocol_cmd("RELOAD_RULES")
    [audit] = valkey.audit("RELOAD_RULES")
    assert audit["ok"] == "false" and "rules not applied" in audit["detail"] and "keeping version 1" in audit["detail"]


def test_reapplying_the_running_rules_is_recorded(valkey):
    _, fw, store = build(rules=V1)
    store.pending = V1
    fw.protocol_cmd("RELOAD_RULES")
    [audit] = valkey.audit("RELOAD_RULES")
    assert "re-applied the running rules" in audit["detail"]


def test_a_load_failure_is_audited_once_not_per_reconnect(valkey):
    iface, fw, store = build(rules=V1)
    store.original = "{ broken"
    store.active = None
    fw.ruleset = fw.ruleset.deny_all()  # a fresh start that cannot load
    for _ in range(3):
        iface.disconnect()
        iface.connect()
    failures = [a for a in valkey.audit("LOAD_RULES") if a["ok"] == "false"]
    assert len(failures) == 1 and "rules not loaded" in failures[0]["detail"]
