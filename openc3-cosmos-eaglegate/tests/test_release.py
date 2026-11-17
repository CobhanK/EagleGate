"""RELEASE (eaglegate_release.py): an admin sends one quarantined packet on into
COSMOS. Only framed, whole, unaltered entries; only once; only with an admin
request; the rules are not checked again (decision C6)."""
import hashlib
import json

import eaglegate_quarantine
import eaglegate_release
import pytest
from conftest import hk_status, rules_json, status_3
from eaglegate_firewall_protocol import EaglegateFirewallProtocol
from eaglegate_release import ReleaseError, check_entry, release_params
from eaglegate_test_support import FakeRulesStore, ScriptedInterface, admin_request
from fake_store import FakeStore

PLUGIN_ARGS = ["1024", "EAGLEGATE/rules/firewall_rules.json"]
QUARANTINE = "DEFAULT__EAGLEGATE__QUARANTINE__EAGLEGATE_INT"
RAW = "DEFAULT__EAGLEGATE__QUARANTINE_RAW__EAGLEGATE_INT"
RELEASED = "DEFAULT__EAGLEGATE__QUARANTINE_RELEASED__EAGLEGATE_INT"


@pytest.fixture
def store(monkeypatch):
    """Every QuarantineWriter boundary goes to one in-memory Valkey."""
    fake = FakeStore()
    W = eaglegate_quarantine.QuarantineWriter
    monkeypatch.setattr(W, "_write", lambda self, stream, fields, maxlen: fake.xadd(stream, fields, maxlen=maxlen))
    monkeypatch.setattr(W, "_range", lambda self, stream, i: fake.xrange(stream, i, i, count=1))
    monkeypatch.setattr(W, "_hsetnx", lambda self, key, field, value: fake.hsetnx(key, field, value))
    monkeypatch.setattr(W, "_hget", lambda self, key, field: fake.hget(key, field))
    monkeypatch.setattr(W, "_hdel", lambda self, key, field: fake.hdel(key, field))
    return fake


def firewall(chunks):
    """Allows APID 2 only; the first packet is allowed, so later rejections
    leave the connection trusted."""
    rules = FakeRulesStore(rules_json([{"id": "allow-hk", "action": "ALLOW", "match": {"apid": [2]}}]))
    iface = ScriptedInterface([hk_status()] + chunks)
    fw = iface.add_protocol(EaglegateFirewallProtocol, PLUGIN_ARGS, "READ")
    fw.store = lambda: rules
    delivered = []
    fw._deliver = lambda data, entry_id: (delivered.append((data, entry_id)), ("EAGLEGATE", "STATUS_3"))[1]
    iface.connect()
    while iface.read() is not None:
        pass
    return iface, fw, rules, delivered


def request_release(rules, entry_id, digest, **kwargs):
    text, sha = admin_request(kind="release", reason="APID 3 was wrongly denied",
                              params={"entry_id": entry_id, "sha256": digest}, **kwargs)
    rules.requests["release"] = text
    return sha


def only_entry(store, stream=QUARANTINE):
    [(entry_id, fields)] = store.streams[stream]
    return entry_id, fields


def test_release_delivers_the_reviewed_packet_once(store):
    _, fw, rules, delivered = firewall([status_3()])
    entry_id, fields = only_entry(store)
    digest = hashlib.sha256(status_3()).hexdigest()
    assert fields[b"sha256"].decode() == digest

    assert fw.protocol_cmd("RELEASE", request_release(rules, entry_id, digest)) is True
    assert delivered == [(status_3(), entry_id)]
    action = fw.admin_actions[-1]
    assert action["ok"] is True and action["action"] == "RELEASE"
    assert "the rules were not checked again" in action["detail"] and "EAGLEGATE STATUS_3" in action["detail"]
    assert (action["entry_id"], action["sha256"], action["apid"]) == (entry_id, digest, "0x003")
    record = json.loads(store.hget(RELEASED, entry_id))
    assert record["reason"] == "APID 3 was wrongly denied" and record["sha256"] == digest
    assert fw.released == 1 and fw.status_items()["RELEASED"] == 1
    assert "release" not in rules.requests  # consumed

    # A second request for the same entry (a new nonce, so not a replay) is refused
    fw.protocol_cmd("RELEASE", request_release(rules, entry_id, digest))
    assert len(delivered) == 1
    assert "already released at" in fw.admin_actions[-1]["detail"]


def test_release_is_audited(store):
    _, fw, rules, _ = firewall([status_3()])
    entry_id, _ = only_entry(store)
    fw.protocol_cmd("RELEASE", request_release(rules, entry_id, hashlib.sha256(status_3()).hexdigest()))
    [audit] = [f for _, f in store.streams["DEFAULT__EAGLEGATE__QUARANTINE_AUDIT__EAGLEGATE_INT"]]
    assert audit[b"action"] == b"RELEASE" and audit[b"ok"] == b"true" and audit[b"entry_id"] == entry_id.encode()


def test_release_needs_the_sha256_that_was_reviewed(store):
    _, fw, rules, delivered = firewall([status_3()])
    entry_id, _ = only_entry(store)
    fw.protocol_cmd("RELEASE", request_release(rules, entry_id, "0" * 64))
    assert delivered == [] and "not the packet that was reviewed" in fw.admin_actions[-1]["detail"]
    assert store.hget(RELEASED, entry_id) is None


def test_release_needs_an_admin_request(store):
    _, fw, rules, delivered = firewall([status_3()])
    entry_id, _ = only_entry(store)
    request_release(rules, entry_id, hashlib.sha256(status_3()).hexdigest())
    fw.protocol_cmd("RELEASE", "f" * 64)  # an operator guessing, or a stale page
    assert delivered == [] and "does not match the command" in fw.admin_actions[-1]["detail"]
    fw.protocol_cmd("RELEASE")
    assert delivered == []


def test_raw_entries_can_never_be_released(store):
    # A bad CCSDS version is a STRUCTURAL rejection: stored in the RAW stream
    bad = bytes([0xE0]) + status_3()[1:]
    _, fw, rules, delivered = firewall([bad])
    entry_id, fields = only_entry(store, RAW)
    assert fields[b"releasable"] == b"false"
    fw.protocol_cmd("RELEASE", request_release(rules, entry_id, hashlib.sha256(bad).hexdigest()))
    assert delivered == [] and "does not exist" in fw.admin_actions[-1]["detail"]


def test_a_damaged_entry_is_refused(store):
    _, fw, rules, delivered = firewall([status_3()])
    entry_id, fields = only_entry(store)
    fields[b"bytes"] = fields[b"bytes"][:-1] + b"\x01"  # changed in Valkey after it was stored
    fw.protocol_cmd("RELEASE", request_release(rules, entry_id, hashlib.sha256(status_3()).hexdigest()))
    assert delivered == [] and "is damaged" in fw.admin_actions[-1]["detail"]


def test_a_failed_delivery_can_be_retried(store):
    _, fw, rules, _ = firewall([status_3()])
    entry_id, _ = only_entry(store)
    digest = hashlib.sha256(status_3()).hexdigest()

    def unknown(data, entry):
        raise ReleaseError("COSMOS does not recognise this packet as telemetry of EAGLEGATE")

    fw._deliver = unknown
    fw.protocol_cmd("RELEASE", request_release(rules, entry_id, digest))
    assert "was not delivered: COSMOS does not recognise" in fw.admin_actions[-1]["detail"]
    assert store.hget(RELEASED, entry_id) is None  # unclaimed, so it can be released later
    delivered = []
    fw._deliver = lambda data, entry: (delivered.append(entry), ("EAGLEGATE", "STATUS_3"))[1]
    fw.protocol_cmd("RELEASE", request_release(rules, entry_id, digest))
    assert delivered == [entry_id] and fw.admin_actions[-1]["ok"] is True


def test_valkey_trouble_is_reported_not_raised(store, monkeypatch):
    _, fw, rules, delivered = firewall([status_3()])
    entry_id, _ = only_entry(store)

    def down(self, stream, i):
        raise ConnectionError("valkey down")

    monkeypatch.setattr(eaglegate_quarantine.QuarantineWriter, "_range", down)
    fw.protocol_cmd("RELEASE", request_release(rules, entry_id, hashlib.sha256(status_3()).hexdigest()))
    assert delivered == [] and "could not read quarantine entry" in fw.admin_actions[-1]["detail"]


def test_details_count_releases(store):
    iface, fw, rules, _ = firewall([status_3()])
    entry_id, _ = only_entry(store)
    fw.protocol_cmd("RELEASE", request_release(rules, entry_id, hashlib.sha256(status_3()).hexdigest()))
    firewall_details = iface.details()["read_protocols"][0]["firewall"]
    assert firewall_details["released"] == 1
    assert firewall_details["quarantine"]["streams"]["released"] == RELEASED


# ---- the checks on their own ----

@pytest.mark.parametrize("params, message", [
    ({}, "entry_id must be"),
    ({"entry_id": "1-0; DEL x", "sha256": "0" * 64}, "entry_id must be"),
    ({"entry_id": "1-0", "sha256": "ABC"}, "sha256 must be"),
    ({"entry_id": "1-0\n", "sha256": "0" * 64}, "entry_id must be"),
    ({"entry_id": "1-0", "sha256": "0" * 64 + "\n"}, "sha256 must be"),
    ({"entry_id": "1-0", "sha256": "0" * 64, "force": True}, "unknown release parameter"),
])
def test_release_params_are_checked(params, message):
    with pytest.raises(ReleaseError, match=message):
        release_params(params)


def entry(data=b"\x00\x03", **overrides):
    fields = {"releasable": b"true", "truncated": b"false", "interface": b"EAGLEGATE_INT", "stage": b"RULE",
              "bytes": data, "sha256": hashlib.sha256(data).hexdigest().encode()}
    fields.update(overrides)
    return fields


def test_check_entry():
    digest = hashlib.sha256(b"\x00\x03").hexdigest()
    assert check_entry(entry(), "1-0", "EAGLEGATE_INT", digest) == b"\x00\x03"
    with pytest.raises(ReleaseError, match="holds only part"):
        check_entry(entry(truncated=b"true"), "1-0", "EAGLEGATE_INT", digest)
    with pytest.raises(ReleaseError, match="belongs to EAGLEGATE_INT"):
        check_entry(entry(), "1-0", "OTHER_INT", digest)
    with pytest.raises(ReleaseError, match="not releasable"):
        check_entry(entry(releasable=b"false"), "1-0", "EAGLEGATE_INT", digest)


# ---- delivery into COSMOS (the COSMOS classes replaced) ----

class FakeTelemetry:
    def __init__(self, definition):
        self.definition = definition
        self.asked = []

    def identify(self, data, target_names):
        self.asked.append((bytes(data), list(target_names)))
        return self.definition


def cosmos(monkeypatch, definition):
    from openc3.models import target_model
    from openc3.system import system
    from openc3.topics import telemetry_topic

    written, telemetry = [], FakeTelemetry(definition)
    monkeypatch.setattr(system, "System", type("System", (), {"telemetry": telemetry}))
    monkeypatch.setattr(target_model.TargetModel, "sync_tlm_packet_counts",
                        classmethod(lambda cls, packet, names, scope: None))
    monkeypatch.setattr(telemetry_topic.TelemetryTopic, "write_packet",
                        classmethod(lambda cls, packet, scope, queued=False: written.append((packet, scope))))
    return written, telemetry


def test_deliver_writes_a_copy_tagged_as_released(monkeypatch):
    from openc3.packets.packet import Packet

    definition = Packet("EAGLEGATE", "STATUS_3")
    written, telemetry = cosmos(monkeypatch, definition)
    iface = ScriptedInterface()
    iface.tlm_target_names = ["EAGLEGATE"]
    assert eaglegate_release.deliver(iface, status_3(), "5-0", "DEFAULT") == ("EAGLEGATE", "STATUS_3")
    [(packet, scope)] = written
    assert packet is not definition and bytes(packet.buffer) == status_3() and scope == "DEFAULT"
    assert packet.extra == {"eaglegate_released": "5-0"} and packet.received_time is not None
    assert definition.extra is None  # the shared definition was not touched
    assert telemetry.asked == [(status_3(), ["EAGLEGATE"])]


def test_deliver_refuses_unknown_packets_and_disabled_targets(monkeypatch):
    from openc3.packets.packet import Packet

    iface = ScriptedInterface()
    iface.tlm_target_names = ["EAGLEGATE"]
    written, _ = cosmos(monkeypatch, None)
    with pytest.raises(ReleaseError, match="does not recognise"):
        eaglegate_release.deliver(iface, status_3(), "5-0", "DEFAULT")
    written, _ = cosmos(monkeypatch, Packet("EAGLEGATE", "STATUS_3"))
    iface.tlm_target_enabled = {"EAGLEGATE": False}
    with pytest.raises(ReleaseError, match="disabled"):
        eaglegate_release.deliver(iface, status_3(), "5-0", "DEFAULT")
    iface.tlm_target_names = []
    with pytest.raises(ReleaseError, match="maps no telemetry targets"):
        eaglegate_release.deliver(iface, status_3(), "5-0", "DEFAULT")
    assert written == []
