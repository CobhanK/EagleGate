"""Quarantine retention settings and exports (decision C14)."""
import json
import os
import struct
import sys

import eaglegate_quarantine
import pytest
from conftest import ROOT, ccsds, hk_status, rules_json, status_3
from eaglegate_quarantine import QuarantineWriter, entry_fields
from eaglegate_rules_error import RulesError
from eaglegate_rules_parser import parse_rules
from eaglegate_verdict import RULE, STRUCTURAL, Verdict
from fake_store import FakeStore
from test_firewall_protocol import build, read_all

sys.path.insert(0, os.path.join(ROOT, "microservices", "EAGLEGATE_QUARANTINE"))
import eaglegate_quarantine_review as review
import eaglegate_quarantine_service as service

ALLOW_HK = {"id": "allow-hk", "action": "ALLOW", "match": {"apid": [2]}}
SCOPE, IFACE = "DEFAULT", "EAGLEGATE_INT"
K = review.keys(SCOPE, IFACE)


# ---- retention -----------------------------------------------------------------

def test_retention_settings_reach_the_writer(valkey):
    rules = rules_json([ALLOW_HK], settings={"quarantine_max_entries": 500, "quarantine_raw_max_entries": 200,
                                             "quarantine_raw_capture_bytes": 300, "audit_max_entries": 2000})
    garbage = ccsds(2, version=5) + bytes(1000)
    iface, fw, _ = build([hk_status() + status_3()], rules=rules)
    read_all(iface)
    iface.chunks = [garbage]
    read_all(iface)
    framed, raw = valkey.entries
    assert (framed[2], raw[2]) == (500, 200)
    assert len(raw[1]["bytes"]) == 300
    assert valkey.audits[0][2] == 2000
    assert fw.quarantine.summary()["retention"]["quarantine_max_entries"] == 500


def test_untrusted_evidence_follows_the_capture_setting(valkey):
    rules = rules_json([ALLOW_HK], settings={"quarantine_raw_capture_bytes": 256})
    iface, fw, _ = build([status_3() + bytes(2000)], rules=rules)
    read_all(iface)
    assert fw.connection_untrusted and fw.untrusted_captured == 256


def test_age_trim_runs_at_most_once_a_minute(monkeypatch):
    trims = []
    writer = QuarantineWriter("DEFAULT", IFACE)
    monkeypatch.setattr(writer, "_trim", lambda stream, minid: trims.append((stream, minid)))
    writer._trim_by_age(now=0, wall=10 * 86400)
    assert trims == []  # 0 days: no age limit
    writer.settings = {**writer.settings, "quarantine_max_age_days": 2}
    writer._trim_by_age(now=100, wall=10 * 86400)
    assert trims == [(K["quarantine"], f"{8 * 86400 * 1000}-0"), (K["raw"], f"{8 * 86400 * 1000}-0")]
    writer._trim_by_age(now=130, wall=10 * 86400)
    assert len(trims) == 2  # within TRIM_INTERVAL
    writer._trim_by_age(now=100 + eaglegate_quarantine.TRIM_INTERVAL, wall=10 * 86400)
    assert len(trims) == 4


@pytest.mark.parametrize("settings, message", [
    ({"quarantine_max_entries": 50}, "out of range 100..100000"),
    ({"quarantine_raw_capture_bytes": 100000}, "out of range 256..65536"),
    ({"quarantine_max_age_days": -1}, "out of range 0..3650"),
    ({"audit_max_entries": 10}, "out of range 1000..1000000"),
])
def test_bad_retention_settings_are_refused(settings, message):
    with pytest.raises(RulesError, match=message):
        parse_rules(rules_json([], settings=settings))


def test_the_review_service_never_caps_the_audit_stream():
    store = FakeStore()
    store.xadd(K["quarantine"], entry_fields(Verdict(action="DENY", stage=RULE, rule_id="r", detail="d"),
                                             status_3(), IFACE, 1, "t"))
    for i in range(3):
        store.xadd(K["audit"], {"action": "OLD", "n": i})
    entry_id = store.streams[K["quarantine"]][0][0]
    review.set_review(store, K, IFACE, "quarantine", [entry_id], "reviewed", "", "", "")
    assert store.xlen(K["audit"]) == 4  # nothing trimmed: the firewall owns the cap


# ---- export --------------------------------------------------------------------

def fill(store, n=5):
    ids = []
    for i in range(n):
        v = Verdict(action="DENY", stage=RULE, rule_id="deny-3", detail=f"number {i}", rules_version=1)
        ids.append(store.xadd(K["quarantine"], entry_fields(v, ccsds(3, bytes([i]) * 4, seq=i), IFACE, 1,
                                                            f"2026-11-16T12:00:0{i}.250000Z")).decode())
    v = Verdict(action="DENY", stage=STRUCTURAL, detail="bad version")
    store.xadd(K["raw"], entry_fields(v, b"\xe0" + bytes(5000), IFACE, 1, "2026-11-16T12:00:09.000000Z"))
    return ids


class Admin:
    def require_admin(self, token, scope):
        if token != "admin":
            raise service.HttpError(403, "the quarantine is for admins only")
        return "alice"


def app(store):
    return service.ReviewApp(admin_check=Admin(), store=lambda: store)


def export(web, query, token="admin"):
    return web.handle("GET", f"/eaglegate-quarantine/export?scope={SCOPE}&interface={IFACE}&{query}",
                      {"Authorization": token})


def test_json_export_has_everything_and_is_audited():
    store = FakeStore()
    ids = fill(store)
    status, download = export(app(store), "limit=3&format=json")
    assert status == 200 and isinstance(download, service.Download)
    assert download.content_type == "application/json"
    assert download.filename.startswith("eaglegate-EAGLEGATE_INT-quarantine-") and download.filename.endswith(".json")
    doc = json.loads(download.body)
    assert (doc["format"], doc["count"], doc["exported_by"], doc["complete"]) == \
        ("eaglegate-quarantine-export", 3, "alice", False)  # 2 older matches were left out
    assert [e["id"] for e in doc["entries"]] == ids[::-1][:3]
    assert doc["entries"][0]["bytes_hex"] == ccsds(3, bytes([4]) * 4, seq=4).hex()
    [(_, audit)] = [e for e in store.streams[K["audit"]] if e[1][b"action"] == b"EXPORT"]
    assert (audit[b"format"], audit[b"count"], audit[b"user"]) == (b"json", b"3", b"alice")
    assert doc["audit_id"]
    _, everything = export(app(store), "limit=10&format=json")
    assert json.loads(everything.body)["complete"] is True


def test_pcap_export_is_a_valid_capture_oldest_first():
    store = FakeStore()
    fill(store, 2)
    _, download = export(app(store), "format=pcap")
    data = download.body
    magic, major, minor, _, _, snaplen, linktype = struct.unpack("<IHHiIII", data[:24])
    assert (magic, major, minor, linktype) == (0xA1B2C3D4, 2, 4, 147) and snaplen >= 65536
    offset, packets = 24, []
    while offset < len(data):
        seconds, micros, incl, orig = struct.unpack("<IIII", data[offset:offset + 16])
        packets.append((seconds, micros, data[offset + 16:offset + 16 + incl], orig))
        offset += 16 + incl
    assert [p[2] for p in packets] == [ccsds(3, bytes([0]) * 4, seq=0), ccsds(3, bytes([1]) * 4, seq=1)]
    assert packets[0][1] == 250000 and packets[1][0] - packets[0][0] == 1
    assert download.content_type == "application/vnd.tcpdump.pcap"


def test_pcap_keeps_the_original_length_of_truncated_raw_entries():
    store = FakeStore()
    fill(store, 0)
    _, download = export(app(store), "stream=raw&format=pcap")
    _, _, incl, orig = struct.unpack("<IIII", download.body[24:40])
    assert (incl, orig) == (eaglegate_quarantine.RAW_CAPTURE_BYTES, 5001)


def test_export_filters_and_limits():
    store = FakeStore()
    fill(store)
    _, download = export(app(store), "search=number%202&format=json")
    assert [e["detail"] for e in json.loads(download.body)["entries"]] == ["number 2"]
    status, payload = export(app(store), "limit=20000")
    assert status == 400 and "limit must be 1 to 10000" in payload["error"]
    status, payload = export(app(store), "format=csv")
    assert status == 400 and "format must be one of" in payload["error"]


def test_only_admins_can_export():
    store = FakeStore()
    fill(store)
    status, payload = export(app(store), "format=json", token="operator")
    assert status == 403 and set(payload) == {"error"}
    assert K["audit"] not in store.streams


def test_export_reads_past_one_scan_when_asked_for_more():
    store = FakeStore()
    for i in range(review.MAX_SCAN + 5):
        store.xadd(K["quarantine"], {"stage": "RULE", "detail": "x", "bytes": b"\x00"})
    result = review.export_entries(store, K, review.export_query({"limit": "10000"})[0])
    assert len(result["entries"]) == 10000
