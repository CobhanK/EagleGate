"""The audit log viewer (decision C15): the review microservice lists and
exports the audit stream for admins, cleaned like everything else it serves."""
import json
import os
import sys

import pytest
from conftest import ROOT, hk_status, rules_json
from fake_store import FakeStore
from test_firewall_protocol import build

sys.path.insert(0, os.path.join(ROOT, "microservices", "EAGLEGATE_QUARANTINE"))
import eaglegate_quarantine_review as review
import eaglegate_quarantine_service as service

SCOPE, IFACE = "DEFAULT", "EAGLEGATE_INT"
K = review.keys(SCOPE, IFACE)


def fill(store):
    store.xadd(K["audit"], {"time": "t1", "action": "LOAD_RULES", "ok": "true", "detail": "loaded the original rules",
                            "version": 1, "changes": json.dumps({"added": ["allow-hk"]})})
    store.xadd(K["audit"], {"time": "t2", "action": "RELOAD_RULES", "ok": "false",
                            "detail": "rules not applied: bad JSON", "reason": "tighten APID 3",
                            "requested_by": "alice"})
    store.xadd(K["audit"], {"time": "t3", "action": "RELEASE", "ok": "true", "detail": "released entry 5-0",
                            "reason": "false positive\x1b[2J", "requested_by": "bob", "entry_id": "5-0"})


class Admin:
    def require_admin(self, token, scope):
        if token != "admin":
            raise service.HttpError(403, "the quarantine is for admins only")
        return "carol"


def get(store, path, token="admin"):
    web = service.ReviewApp(admin_check=Admin(), store=lambda: store)
    return web.handle("GET", f"/eaglegate-quarantine/{path}{'&' if '?' in path else '?'}scope={SCOPE}"
                             f"&interface={IFACE}", {"Authorization": token})


def test_newest_first_with_common_fields_and_details():
    store = FakeStore()
    fill(store)
    status, payload = get(store, "audit")
    assert status == 200
    assert [e["action"] for e in payload["entries"]] == ["RELEASE", "RELOAD_RULES", "LOAD_RULES"]
    release, reload_, load = payload["entries"]
    assert release["ok"] is True and reload_["ok"] is False
    assert release["reason"] == "false positive\\x1b[2J"  # cleaned
    assert release["fields"] == {"entry_id": "5-0"}
    assert load["fields"]["changes"] == {"added": ["allow-hk"]}  # JSON fields come parsed
    assert payload["actions"] == ["LOAD_RULES", "RELEASE", "RELOAD_RULES"]
    assert payload["stream_length"] == 3 and payload["next_before"] is None


def test_filters_and_paging():
    store = FakeStore()
    fill(store)
    assert [e["action"] for e in get(store, "audit?action=release")[1]["entries"]] == ["RELEASE"]
    assert [e["action"] for e in get(store, "audit?ok=false")[1]["entries"]] == ["RELOAD_RULES"]
    assert [e["action"] for e in get(store, "audit?search=alice")[1]["entries"]] == ["RELOAD_RULES"]
    assert [e["action"] for e in get(store, "audit?search=allow-hk")[1]["entries"]] == ["LOAD_RULES"]
    first = get(store, "audit?limit=1")[1]
    second = get(store, f"audit?limit=1&before={first['next_before']}")[1]
    assert (first["entries"][0]["action"], second["entries"][0]["action"]) == ("RELEASE", "RELOAD_RULES")


@pytest.mark.parametrize("query, message", [
    ("audit?action=drop;table", "action must be an action name"),
    ("audit?ok=maybe", "ok must be true or false"),
    ("audit?limit=0", "limit must be 1 to 1000"),
    ("audit?before=x", "before must be"),
])
def test_bad_filters(query, message):
    status, payload = get(FakeStore(), query)
    assert status == 400 and message in payload["error"]


def test_only_admins_see_the_audit_log():
    store = FakeStore()
    fill(store)
    status, payload = get(store, "audit", token="operator")
    assert status == 403 and set(payload) == {"error"}
    status, payload = get(store, "audit/export", token="operator")
    assert status == 403


def test_export_is_a_json_download_and_is_itself_audited():
    store = FakeStore()
    fill(store)
    status, download = get(store, "audit/export?ok=true")
    assert status == 200 and download.content_type == "application/json"
    assert download.filename.startswith("eaglegate-EAGLEGATE_INT-audit-")
    doc = json.loads(download.body)
    assert (doc["format"], doc["count"], doc["exported_by"], doc["complete"]) == \
        ("eaglegate-audit-export", 2, "carol", True)
    newest = get(store, "audit?limit=1")[1]["entries"][0]
    assert (newest["action"], newest["user"], newest["fields"]["stream"]) == ("EXPORT", "carol", "audit")


def test_the_firewalls_own_entries_show_up(valkey):
    """End to end with the firewall's writer: its LOAD_RULES entry reads back."""
    store = FakeStore()
    build([hk_status()], rules=rules_json([{"id": "allow-hk", "action": "ALLOW",
                                                        "match": {"apid": [2]}}]))
    for stream, fields, _ in valkey.audits:
        store.xadd(stream, fields)
    [entry] = get(store, "audit")[1]["entries"]
    assert entry["action"] == "LOAD_RULES" and entry["ok"] is True
    assert entry["fields"]["changes"]["added"] == ["allow-hk"] and entry["fields"]["version"] == "1"
