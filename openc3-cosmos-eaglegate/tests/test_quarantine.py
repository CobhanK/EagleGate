"""Quarantine tests: the reason each rule gives, what is stored for rejected
packets, the interface_details summary and the FIREWALL_STATUS packet.
Valkey is faked by the `valkey` fixture in conftest.py."""
import hashlib
import hmac
import json
import os
import struct

import pytest
from hypothesis import given, settings, strategies as st

import eaglegate_firewall_protocol
import eaglegate_quarantine
from conftest import REAL_INJECT, REAL_WRITE, ROOT, ccsds, hk_status, rules_json, status_3
from eaglegate_quarantine import QUARANTINE_MAXLEN, RAW_CAPTURE_BYTES, RAW_MAXLEN, STATUS_STRING_CHARS
from eaglegate_rules_parser import parse_rules
from openc3.utilities.json import JsonDecoder, JsonEncoder
from test_firewall_protocol import ALLOW_ALL, apids, build, read_all

KEY_HEX = "00112233445566778899aabbccddeeff"
TLM_TXT = os.path.join(ROOT, "targets", "EAGLEGATE", "cmd_tlm", "tlm.txt")


def deny_check(rule_type, params, description=""):
    """One check rule above allow-everything, so the check is the only filter."""
    return parse_rules(rules_json([
        {"id": rule_type, "type": rule_type, "action": "DENY", "match": {},
         "params": params, "description": description},
        {"id": "allow-all", "action": "ALLOW", "match": {}},
    ]))


# ---- the reason each rule gives ----

def test_range_reason_names_value_and_limits():
    rs = deny_check("range", {"offset": 6, "data_type": "INT16", "min": -40, "max": 85})
    verdict = rs.evaluate(ccsds(2, struct.pack(">h", 120)))
    assert verdict.detail == "INT16 at offset 6 = 120, allowed -40..85"
    assert rs.evaluate(ccsds(2, b"\x00")).detail == "packet is 7 bytes, too short for INT16 at offset 6"
    upper_only = deny_check("range", {"offset": 6, "data_type": "UINT8", "max": 10})
    assert upper_only.evaluate(ccsds(2, b"\xff")).detail == "UINT8 at offset 6 = 255, allowed <= 10"


@pytest.mark.parametrize("seq, found", [
    (10, "repeats the last allowed count"),
    (13, "is 3 ahead"),
    (8, "is 2 behind"),
])
def test_sequence_reason_says_which_way(seq, found):
    rs = deny_check("sequence", {})
    rs.evaluate(ccsds(2, seq=10))
    assert rs.evaluate(ccsds(2, seq=seq)).detail == f"sequence count {seq} {found} (last allowed 10, max_gap 1)"


def test_rate_reason_gives_the_gap():
    rs = deny_check("rate", {"min_interval": 0.9})
    rs.evaluate(ccsds(2), now=100.0)
    assert rs.evaluate(ccsds(2), now=100.25).detail == \
        "0.250 s after the last allowed packet, min_interval 0.9 s"


def test_authenticity_reason_shows_received_mac_never_expected(monkeypatch):
    monkeypatch.setenv("TEST_AUTH_KEY", KEY_HEX)
    rs = deny_check("authenticity", {"key_env": "TEST_AUTH_KEY", "mac_bytes": 8})
    unsigned = ccsds(2, b"hello" + bytes(8))[:-8]
    expected = hmac.new(bytes.fromhex(KEY_HEX), unsigned, hashlib.sha256).digest()[:8]
    received = bytes.fromhex("deadbeef00112233")
    detail = rs.evaluate(unsigned + received).detail
    assert detail == "MAC mismatch, received deadbeef00112233"
    assert expected.hex() not in detail
    assert rs.evaluate(ccsds(2, b"ab")).detail == "packet is 8 bytes, too short for the security fields (14 bytes)"


def test_authenticity_reason_names_wrong_spi(monkeypatch):
    monkeypatch.setenv("TEST_AUTH_KEY", KEY_HEX)
    rs = deny_check("authenticity", {"key_env": "TEST_AUTH_KEY", "spi": 1, "mac_bytes": 8})
    assert rs.evaluate(ccsds(2, b"\x00\x02" + bytes(10))).detail == "SPI 0x0002, expected 0x0001"


def test_match_and_default_reasons():
    rs = parse_rules(rules_json([
        {"id": "no-cmds", "action": "DENY", "description": "Commands never belong here",
         "match": {"packet_type": "CMD", "apid": [2, 3], "max_length": 64}},
    ]))
    verdict = rs.evaluate(ccsds(2, packet_type=1))
    assert verdict.detail == "matched APID 0x002,0x003; type CMD; length ..64"
    assert (verdict.rule_type, verdict.rule_description) == ("match", "Commands never belong here")
    assert verdict.reason() == "DENY by rule 'no-cmds': matched APID 0x002,0x003; type CMD; length ..64 (rules v1)"
    default = rs.evaluate(ccsds(9))
    assert (default.stage, default.rule_id) == ("DEFAULT", None)
    assert default.reason() == "DENY by default action: no rule fired; default action DENY (rules v1)"


def test_description_must_be_a_string():
    with pytest.raises(Exception, match="description must be a string"):
        parse_rules(rules_json([{"id": "r", "action": "DENY", "match": {}, "description": 5}]))


# ---- what is stored for a rejected packet ----

def test_rule_denied_packet_is_stored_whole_with_its_reason(valkey):
    bad = hk_status(packet_type=1, seq=7)
    iface, proto, _ = build([hk_status() + bad + status_3()])
    assert apids(read_all(iface)) == [2, 3]
    [entry] = valkey.stream("__EAGLEGATE__QUARANTINE__EAGLEGATE_INT")
    assert entry["bytes"] == bad and entry["length"] == len(bad) and entry["truncated"] == "false"
    assert entry["sha256"] == hashlib.sha256(bad).hexdigest()
    assert (entry["apid"], entry["seq_count"], entry["packet_type"]) == ("0x002", 7, "CMD")
    assert (entry["stage"], entry["rule_id"], entry["rule_type"]) == ("RULE", "deny-commands-on-tlm-link", "match")
    assert entry["rule_description"].startswith("Command-type packets never belong")
    assert entry["detail"] == "matched type CMD"
    assert (entry["rules_version"], entry["rules_sha256"]) == (1, proto.ruleset.sha256)
    assert entry["releasable"] == "true"
    assert (entry["interface"], entry["connection_id"]) == ("EAGLEGATE_INT", 1)
    assert valkey.entries[0][0] == "DEFAULT__EAGLEGATE__QUARANTINE__EAGLEGATE_INT"
    assert valkey.entries[0][2] == QUARANTINE_MAXLEN


def test_stream_fields_are_types_valkey_accepts(valkey):
    iface, _, _ = build([hk_status() + ccsds(0x100) + ccsds(2, version=5)])
    read_all(iface)
    for _, fields, _ in valkey.entries:
        for name, value in fields.items():
            assert isinstance(value, (str, bytes, int)) and not isinstance(value, bool), name


def test_structural_reject_goes_to_raw_stream_cut_to_capture_size(valkey):
    garbage = ccsds(2, version=5) + bytes(RAW_CAPTURE_BYTES * 2)
    iface, _, _ = build([hk_status(), garbage], rules=ALLOW_ALL)
    read_all(iface)
    [entry] = valkey.stream("__EAGLEGATE__QUARANTINE_RAW__EAGLEGATE_INT")
    assert entry["stage"] == "STRUCTURAL" and entry["releasable"] == "false"
    assert entry["detail"] == f"bad CCSDS version 5; discarded {len(garbage)} buffered bytes"
    assert entry["bytes"] == garbage[:RAW_CAPTURE_BYTES]
    assert (entry["length"], entry["truncated"]) == (len(garbage), "true")
    assert [m for _, _, m in valkey.entries] == [RAW_MAXLEN]
    assert valkey.stream("__QUARANTINE__EAGLEGATE_INT") == []  # nothing framed was rejected


def test_untrusted_connection_keeps_only_first_bytes_as_evidence(valkey):
    first = ccsds(0x100)
    chunks = [first + bytes(3000), bytes(3000), bytes(3000)]
    iface, proto, _ = build(chunks)
    assert read_all(iface) == []
    framed = valkey.stream("__QUARANTINE__EAGLEGATE_INT")
    raw = valkey.stream("__QUARANTINE_RAW__EAGLEGATE_INT")
    assert [e["stage"] for e in framed] == ["DEFAULT"]  # the first packet, judged and whole
    assert [e["stage"] for e in raw] == ["UNTRUSTED", "UNTRUSTED"]
    assert sum(len(e["bytes"]) for e in raw) == RAW_CAPTURE_BYTES  # 3000 + 1096, then nothing
    assert raw[1]["detail"].endswith("discarded 3000 bytes, kept 1096")
    assert proto.discarded_bytes == 9000
    assert proto.last_rejection["stage"] == "DEFAULT"  # the cause stays visible on screens
    assert [r["stage"] for r in proto.recent] == ["DEFAULT", "UNTRUSTED", "UNTRUSTED"]

    iface.chunks = [ccsds(0x100), bytes(10)]  # a reconnect captures again
    iface.connect()
    read_all(iface)
    assert valkey.stream("__QUARANTINE_RAW__EAGLEGATE_INT")[-1]["connection_id"] == 2


def test_valkey_outage_never_changes_decisions(valkey, monkeypatch):
    valkey.fail = True
    clock = [1000.0]
    monkeypatch.setattr(eaglegate_quarantine.time, "monotonic", lambda: clock[0])
    stream = hk_status() + ccsds(0x100) + ccsds(0x101) + status_3()
    iface, proto, _ = build([stream])
    assert apids(read_all(iface)) == [2, 3]
    assert proto.rejected == 2
    summary = proto.quarantine.summary()
    assert (summary["written"], summary["errors"], summary["skipped"]) == (0, 1, 1)  # paused after one
    assert "valkey down" in summary["last_error"]
    assert proto.last_rejection["entry_id"] is None

    valkey.fail = False
    clock[0] += eaglegate_quarantine.PAUSE_AFTER_ERROR
    iface.chunks = [ccsds(0x102)]
    read_all(iface)
    assert proto.last_rejection["entry_id"] == "1-0"  # writing resumes after the pause


# ---- option A: interface_details ----

def test_details_list_recent_reasons_newest_first_without_bytes(valkey):
    stream = hk_status() + b"".join(ccsds(0x10 + i, seq=i) for i in range(25))
    iface, _, _ = build([stream])
    read_all(iface)
    details = json.loads(json.dumps(iface.details(), cls=JsonEncoder), cls=JsonDecoder)  # as COSMOS sends it
    fw = details["read_protocols"][0]["firewall"]
    recent = fw["quarantine"]["recent"]
    assert len(recent) == eaglegate_firewall_protocol.RECENT_REJECTIONS
    assert recent[0]["apid"] == "0x028" and recent[0]["seq_count"] == 24
    assert recent[0]["reason"] == "DENY by default action: no rule fired; default action DENY (rules v1)"
    assert recent[0]["entry_id"] == "25-0"
    assert all("bytes" not in r for r in recent)
    assert fw["rejected_by_stage"] == {"RULE": 0, "DEFAULT": 25, "ERROR": 0, "STRUCTURAL": 0}
    assert fw["quarantine"]["written"] == 25
    assert fw["quarantine"]["streams"]["quarantine"] == "DEFAULT__EAGLEGATE__QUARANTINE__EAGLEGATE_INT"


# ---- option B: FIREWALL_STATUS packet ----

def test_status_published_on_connect_then_throttled(valkey, monkeypatch):
    clock = [500.0]
    monkeypatch.setattr(eaglegate_firewall_protocol.time, "monotonic", lambda: clock[0])
    iface, proto, _ = build([hk_status() + b"".join(ccsds(0x10 + i) for i in range(50))])
    assert len(valkey.status) == 1 and valkey.status[0]["REJECTED"] == 0  # on connect
    assert valkey.status[0]["RULES_VERSION"] == 1
    read_all(iface)
    assert len(valkey.status) == 1  # 50 rejections inside one interval: no packet flood

    clock[0] += eaglegate_firewall_protocol.STATUS_INTERVAL
    iface.chunks = [hk_status()]  # any later read catches up
    read_all(iface)
    latest = valkey.status[-1]
    assert len(valkey.status) == 2
    assert (latest["REJECTED"], latest["DENIED_DEFAULT"], latest["QUARANTINED"]) == (50, 50, 50)
    assert latest["LAST_APID"] == "0x041" and latest["LAST_STAGE"] == "DEFAULT"
    assert latest["LAST_ENTRY_ID"] == "50-0" and latest["CCSDS_VERSION"] == 7


def test_status_reports_untrusted_connection(valkey):
    iface, _, _ = build([ccsds(0x100)])
    read_all(iface)
    assert valkey.status[-1]["CONNECTION_UNTRUSTED"] == "TRUE"
    assert valkey.status[-1]["LAST_STAGE"] == "DEFAULT"


def test_status_failure_never_breaks_the_interface(valkey):
    valkey.fail = True
    iface, proto, _ = build([hk_status() + ccsds(0x100) + status_3()])
    assert apids(read_all(iface)) == [2, 3]
    assert proto.status.errors == 1


def test_reload_publishes_new_rules_version_from_read_thread(valkey, monkeypatch):
    clock = [500.0]
    monkeypatch.setattr(eaglegate_firewall_protocol.time, "monotonic", lambda: clock[0])
    iface, proto, store = build([hk_status()])
    read_all(iface)
    before = len(valkey.status)
    store.text = rules_json([{"id": "allow-all", "action": "ALLOW", "match": {}}], version=4)
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    assert len(valkey.status) == before  # not from the command thread
    clock[0] += eaglegate_firewall_protocol.STATUS_INTERVAL
    iface.chunks = [status_3()]
    read_all(iface)
    assert valkey.status[-1]["RULES_VERSION"] == 4


# ---- FIREWALL_STATUS definition in tlm.txt ----

@pytest.fixture(scope="module")
def packets():
    from openc3.packets.packet_config import PacketConfig
    from openc3.packets.telemetry import Telemetry

    config = PacketConfig()
    config.process_file(TLM_TXT, "EAGLEGATE")
    return config, Telemetry(config, None)


def test_status_items_fit_the_packet_definition(packets):
    """Write every item the way handle_inject_tlm does, with oversized strings."""
    config, _ = packets
    packet = config.telemetry["EAGLEGATE"]["FIREWALL_STATUS"]
    _, proto, _ = build()
    items = proto.status_items()
    items.update({name: "é" * 400 for name in STATUS_STRING_CHARS})
    items["CONNECTION_UNTRUSTED"] = "TRUE"
    for name, value in eaglegate_quarantine.status_items(items).items():
        packet.write(name, value, "CONVERTED")
    for name, chars in STATUS_STRING_CHARS.items():
        assert packet.get_item(name).bit_size == chars * 8, name
    assert packet.read("CONNECTION_UNTRUSTED") == "TRUE"
    assert set(eaglegate_quarantine.status_items(items)) == \
        set(packet.items) - {"SPARE", "PACKET_TIMESECONDS", "PACKET_TIMEFORMATTED",
                             "RECEIVED_TIMESECONDS", "RECEIVED_TIMEFORMATTED", "RECEIVED_COUNT"}


@settings(max_examples=300, deadline=None)
@given(st.binary(min_size=6, max_size=500))
def test_no_packet_the_firewall_lets_through_identifies_as_status(packets, data):
    """Anything leaving the firewall has CCSDS version 0; FIREWALL_STATUS needs 7."""
    _, telemetry = packets
    allowed = bytes([data[0] & 0x1F]) + data[1:]  # version 0, like every allowed packet
    identified = telemetry.identify(allowed, ["EAGLEGATE"])
    assert identified is None or identified.packet_name != "FIREWALL_STATUS"


def test_received_housekeeping_still_identifies(packets):
    _, telemetry = packets
    assert telemetry.identify(hk_status(), ["EAGLEGATE"]).packet_name == "HK_STATUS"
    assert telemetry.identify(status_3(), ["EAGLEGATE"]).packet_name == "STATUS_3"


def test_screen_only_shows_items_that_exist(packets):
    config, _ = packets
    defined = config.telemetry["EAGLEGATE"]
    with open(os.path.join(ROOT, "targets", "EAGLEGATE", "screens", "firewall.txt")) as f:
        widgets = [line.split() for line in f if line.strip().startswith("LABELVALUE")]
    assert widgets
    for _, target, packet, item, *_ in widgets:
        assert target == "EAGLEGATE" and item in defined[packet].items, item


# ---- the real COSMOS calls, with only openc3's internals faked ----

def test_writer_xadds_to_the_persistent_store_with_a_cap(monkeypatch):
    import openc3.utilities.store as store_module

    calls = []

    class FakeStore:
        @classmethod
        def instance(cls):
            return cls()

        def write_topic(self, topic, msg_hash, id="*", maxlen=None, approximate=True):
            calls.append((topic, msg_hash, id, maxlen, approximate))
            return b"1700000000000-0"

    monkeypatch.setattr(store_module, "Store", FakeStore)
    monkeypatch.setattr(eaglegate_quarantine.QuarantineWriter, "_write", REAL_WRITE)
    writer = eaglegate_quarantine.QuarantineWriter("DEFAULT", "EAGLEGATE_INT")
    verdict = parse_rules(rules_json([])).evaluate(ccsds(5))
    assert writer.record(verdict, ccsds(5), 1, "t") == "1700000000000-0"
    [(topic, fields, id_, maxlen, approximate)] = calls
    assert topic == "DEFAULT__EAGLEGATE__QUARANTINE__EAGLEGATE_INT"
    assert (id_, maxlen, approximate) == ("*", QUARANTINE_MAXLEN, True)  # XADD ... MAXLEN ~ 10000
    assert fields["bytes"] == ccsds(5)


def test_status_goes_through_cosmos_inject_tlm_code(monkeypatch, packets):
    """Runs openc3's real handle_inject_tlm (JSON decoding, per-item writes)
    against the real FIREWALL_STATUS definition."""
    import openc3.microservices.interface_decom_common as common

    config, telemetry = packets
    packet = config.telemetry["EAGLEGATE"]["FIREWALL_STATUS"]
    written = []

    class FakeSystem:
        class telemetry:
            @staticmethod
            def packet(target_name, packet_name):
                return config.telemetry[target_name][packet_name]

    monkeypatch.setattr(common, "System", FakeSystem)
    monkeypatch.setattr(common.TargetModel, "increment_telemetry_count", lambda *a, **k: 1)
    monkeypatch.setattr(common.TelemetryTopic, "write_packet", lambda p, scope: written.append(scope))
    monkeypatch.setattr(eaglegate_quarantine.StatusPublisher, "_inject", REAL_INJECT)

    iface, proto, _ = build([hk_status() + ccsds(2, packet_type=1)])
    read_all(iface)
    proto._publish_status_if_due(force=True)
    assert proto.status.errors == 0 and written == ["DEFAULT", "DEFAULT"]  # connect + forced
    assert packet.read("REJECTED") == 1 and packet.read("DENIED_RULE") == 1
    assert packet.read("CONNECTION_UNTRUSTED") == "FALSE" and packet.read("RULES_VERSION") == 1
    assert packet.read("LAST_RULE_ID") == "deny-commands-on-tlm-link"
    assert packet.read("LAST_REASON").startswith("DENY by rule 'deny-commands-on-tlm-link'")
    assert telemetry.identify(bytes(packet.buffer), ["EAGLEGATE"]).packet_name == "FIREWALL_STATUS"


# ---- gaps found in review ----

def test_counters_beyond_32_bits_do_not_break_the_status_packet(packets):
    config, _ = packets
    packet = config.telemetry["EAGLEGATE"]["FIREWALL_STATUS"]
    _, proto, _ = build()
    proto.rejected = proto.discarded_bytes = 2 ** 40
    proto.rejected_by_stage = dict.fromkeys(proto.rejected_by_stage, 2 ** 33)
    for name, value in eaglegate_quarantine.status_items(proto.status_items()).items():
        packet.write(name, value, "CONVERTED")  # would raise for an out-of-range UINT32
    assert packet.read("REJECTED") == 0xFFFFFFFF


def test_failed_status_publish_is_retried(valkey, monkeypatch):
    clock = [500.0]
    monkeypatch.setattr(eaglegate_firewall_protocol.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(eaglegate_quarantine.time, "monotonic", lambda: clock[0])
    iface, proto, _ = build([hk_status()])
    read_all(iface)
    valkey.fail = True
    clock[0] += 5
    iface.chunks = [ccsds(0x100)]
    read_all(iface)
    assert proto.status_due  # still owed to the screen
    valkey.fail = False
    clock[0] += eaglegate_quarantine.PAUSE_AFTER_ERROR
    iface.chunks = [hk_status()]  # no new rejection, but the missed update goes out
    read_all(iface)
    assert valkey.status[-1]["REJECTED"] == 1 and not proto.status_due


def test_untrusted_bytes_are_not_decoded_as_a_header(valkey):
    iface, proto, _ = build([ccsds(0x100), ccsds(0x7FF, seq=99)])
    read_all(iface)
    [entry] = valkey.stream("__QUARANTINE_RAW__EAGLEGATE_INT")
    assert entry["stage"] == "UNTRUSTED"
    assert (entry["apid"], entry["seq_count"], entry["packet_type"]) == ("", "", "")
    assert proto.recent[-1]["apid"] is None


def test_evaluation_error_is_quarantined_as_a_whole_releasable_packet(valkey):
    iface, proto, _ = build([hk_status() + status_3()])

    def broken(packet):
        raise RuntimeError("boom")

    proto.ruleset.evaluate = broken
    read_all(iface)
    [entry] = valkey.stream("__QUARANTINE__EAGLEGATE_INT")
    assert (entry["stage"], entry["releasable"], entry["bytes"]) == ("ERROR", "true", hk_status())
    assert entry["detail"] == "rules engine error: boom"
    assert proto.rejected_by_stage["ERROR"] == 1  # it was the first packet: the rest is untrusted
    assert [e["stage"] for e in valkey.stream("__QUARANTINE_RAW__EAGLEGATE_INT")] == ["UNTRUSTED"]


def test_no_valid_rules_reason_says_so(valkey):
    iface, _, _ = build([hk_status()], rules="{broken")
    read_all(iface)
    [entry] = valkey.stream("__QUARANTINE__EAGLEGATE_INT")
    assert entry["rules_version"] == -1
    assert entry["detail"] == "no valid rules file has been loaded; denying everything (see rules_error)"


def test_retrying_a_dead_link_does_not_publish_status_each_time(valkey):
    """COSMOS calls connect_reset() before opening the socket, so a refused
    connection runs it every few seconds."""
    iface, proto, _ = build([hk_status()])
    read_all(iface)
    published = len(valkey.status)
    for _ in range(10):
        proto.connect_reset()  # connection refused, retried
    assert len(valkey.status) == published


def test_reconnect_publishes_when_untrusted_clears_or_rules_change(valkey, monkeypatch):
    clock = [500.0]
    monkeypatch.setattr(eaglegate_firewall_protocol.time, "monotonic", lambda: clock[0])
    iface, proto, store = build([ccsds(0x100)])
    read_all(iface)
    assert valkey.status[-1]["CONNECTION_UNTRUSTED"] == "TRUE"
    proto.connect_reset()
    assert valkey.status[-1]["CONNECTION_UNTRUSTED"] == "FALSE"  # at once, not throttled
    store.text = rules_json([], version=7)
    proto.connect_reset()
    assert valkey.status[-1]["RULES_VERSION"] == 7
