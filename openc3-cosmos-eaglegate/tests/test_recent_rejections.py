"""FIREWALL_RECENT (decision C9): the last 10 rejections as operator telemetry
for the FIREWALLREJECTIONS widget. Metadata and cleaned reasons, never bytes."""
import json
import os
import sys

from conftest import ROOT, ccsds, hk_status, rules_json, status_3
from eaglegate_quarantine import RECENT_COUNT, RECENT_JSON_BYTES, recent_items
from eaglegate_safe_text import UNSAFE, clean
from eaglegate_verdict import LINK, Verdict
from test_firewall_protocol import build, read_all

sys.path.insert(0, os.path.join(ROOT, "microservices", "EAGLEGATE_QUARANTINE"))
import eaglegate_quarantine_review as review

ALLOW_HK = rules_json([{"id": "allow-hk", "action": "ALLOW", "match": {"apid": [2]}}])


def recent_rows(valkey):
    item_hash = valkey.recent[-1]
    rows = json.loads(item_hash["RECENT_JSON"])
    assert item_hash["RECENT_COUNT"] == len(rows) and item_hash["CCSDS_VERSION"] == 5
    return rows


def test_the_last_ten_rejections_are_published_newest_first(valkey):
    iface, fw, _ = build(rules=ALLOW_HK)
    fw._packet_name = lambda data: "EAGLEGATE STATUS_3"
    iface.chunks = [hk_status()] + [ccsds(3, bytes(4), seq=i) for i in range(12)]
    read_all(iface)
    fw._publish_status_if_due(force=True)
    rows = recent_rows(valkey)
    assert len(rows) == RECENT_COUNT
    assert [r["seq_count"] for r in rows] == list(range(11, 1, -1))
    row = rows[0]
    assert (row["stage"], row["apid"], row["packet_type"], row["packet"], row["length"]) == \
        ("DEFAULT", "0x003", "TLM", "EAGLEGATE STATUS_3", 10)
    assert row["interface"] == "EAGLEGATE_INT" and row["entry_id"] and row["reason"].startswith("DENY by default")
    assert not any(k.startswith("_") or k == "bytes" for r in rows for k in r)


def test_bytes_are_kept_only_until_the_packet_is_named(valkey):
    iface, fw, _ = build(rules=ALLOW_HK)
    named = []
    fw._packet_name = lambda data: named.append(data) or "unknown"
    iface.chunks = [hk_status(), status_3()]
    read_all(iface)
    details = iface.details()["read_protocols"][0]["firewall"]["quarantine"]["recent"]
    assert all("_data" not in r for r in details)  # never shown, even before naming
    fw._publish_status_if_due(force=True)
    assert named == [status_3()] and all("_data" not in r for r in fw.recent)
    fw.recent_due = True
    fw._publish_status_if_due(force=True)
    assert len(named) == 1  # named once


def test_unidentifiable_packets_get_no_name():
    _, fw, _ = build(rules=ALLOW_HK)
    assert fw._packet_name(status_3()) == ""  # no COSMOS System in the tests: cannot say


def test_link_rejections_carry_their_layer_and_link(valkey):
    _, fw, _ = build(rules=ALLOW_HK)
    fw.reject(Verdict(action="DENY", stage=LINK, layer="sdls", detail="MAC check failed", rules_version=1),
              b"\x1a\xcf\xfc\x1d" + bytes(20), {"vcid": 5, "spi": 7})
    fw._publish_status_if_due(force=True)
    [row] = recent_rows(valkey)
    assert (row["stage"], row["layer"], row["link"], row["apid"], row["packet"]) == \
        ("LINK", "sdls", {"vcid": "5", "spi": "7"}, "", "")


def test_text_is_cleaned_and_bounded(valkey):
    _, fw, _ = build(rules=ALLOW_HK)
    fw.reject(Verdict(action="DENY", stage=LINK, layer="frame\u202e", detail="evil \x1b[2J" + "x" * 500,
                      rules_version=1), b"\x00" * 8, {"note\x07": "a\u2028b"})
    fw._publish_status_if_due(force=True)
    text = valkey.recent[-1]["RECENT_JSON"]
    assert not UNSAFE.search(json.loads(text)[0]["reason"])
    [row] = json.loads(text)
    assert row["layer"] == "frame\\u202e" and row["link"] == {"note\\x07": "a\\u2028b"}
    assert "\\x1b[2J" in row["reason"] and len(row["reason"]) <= 161


def test_the_json_stays_within_its_size():
    rejections = [{"time": "t", "stage": "RULE", "rule_id": "r" * 64, "reason": "y" * 2000,
                   "link": {f"k{i}": "v" * 64 for i in range(8)}} for _ in range(10)]
    items = recent_items(rejections)
    assert len(items["RECENT_JSON"]) <= RECENT_JSON_BYTES and items["RECENT_COUNT"] >= 1


def test_empty_list_on_first_connect(valkey):
    build(rules=ALLOW_HK)
    assert valkey.recent and json.loads(valkey.recent[-1]["RECENT_JSON"]) == []


def test_the_microservice_cleans_text_the_same_way():
    assert review.UNSAFE.pattern == UNSAFE.pattern
    for sample in ["ok", "\x1b[0m", "a\u202eb", "\u200b\u2028\ufeff", b"\xff\xfe", "x" * 600]:
        assert review.clean(sample) == clean(sample)
