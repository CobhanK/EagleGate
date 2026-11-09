"""Extension points (eaglegate_extensions.py): a protocol in front of the firewall
that owns a rules section, attaches link information and uses the firewall's
Extension API. Runs the real openc3 Interface read loop with two protocols, so
it also pins down the COSMOS chaining behaviour extensions rely on."""
import json

import pytest

from conftest import ccsds, hk_status, rules_json, status_3
from eaglegate_ccsds_header import CcsdsHeader
from eaglegate_extensions import (FIREWALL_API_VERSION, LINK_EXTRA_KEY, Extension, collect_extensions,
                                  link_of, with_link)
from eaglegate_firewall_protocol import EaglegateFirewallProtocol
from eaglegate_match import Match
from eaglegate_rules_error import RulesError
from eaglegate_rules_parser import TOP_LEVEL_KEYS, parse_rules, rules_schema
from eaglegate_verdict import LINK, Verdict
from eaglegate_test_support import FakeRulesStore, ScriptedInterface
from openc3.interfaces.protocols.protocol import Protocol

PLUGIN_ARGS = ["1024", "EAGLEGATE/rules/firewall_rules.json"]
LINK_KEYS = {
    "vcid": {"type": "int_list", "min": 0, "max": 63, "help": "virtual channel"},
    "protection": {"type": "enum_list", "values": ["clear", "auth"]},
}
BAD_FRAME = 0xFF  # first byte of a fake frame that the fake extension rejects


def parse_fakelink(raw, where):
    if raw is None:
        return {"strict": False}
    if not isinstance(raw, dict) or set(raw) - {"strict"} or not isinstance(raw.get("strict", False), bool):
        raise RulesError(f"{where} must be {{\"strict\": true|false}}")
    return {"strict": raw.get("strict", False)}


def fake_extension(**overrides):
    fields = dict(name="fakelink", section="fakelink", parse=parse_fakelink, link_keys=LINK_KEYS,
                  layers=("frame",), schema={"strict": {"type": "bool", "default": False}}, version="0.1")
    fields.update(overrides)
    return Extension(**fields)


class FakeLinkProtocol(Protocol):
    """A minimal extension: each chunk is a "frame" = 1 byte VCID + whole packets.
    It emits ONE packet per read_data call (with link info in extra), like the SDLS
    frame protocol, and rejects frames whose first byte is BAD_FRAME."""

    def __init__(self, allow_empty_data=None):
        super().__init__(allow_empty_data)
        self.queue = []
        self.first_frame_decided = False
        self.extension = fake_extension()

    def eaglegate_extension(self):
        return self.extension

    def firewall(self):
        return next(p for p in self.interface.read_protocols if getattr(p, "EAGLEGATE_FIREWALL_API", None))

    def connect_reset(self):
        super().connect_reset()
        self.queue = []
        self.first_frame_decided = False

    def read_data(self, data, extra=None):
        firewall = self.firewall()
        if firewall.connection_untrusted:
            firewall.discard_untrusted(data)
            self.queue = []
            return ("STOP", extra)
        if data:
            vcid, body = data[0], data[1:]
            if vcid == BAD_FRAME:
                verdict = Verdict(action="DENY", stage=LINK, layer="frame", detail="bad frame",
                                  rules_version=firewall.ruleset.version, rules_sha256=firewall.ruleset.sha256)
                firewall.reject(verdict, data, {"vcid": None})
                if not self.first_frame_decided:
                    firewall.mark_untrusted("its first frame was rejected", verdict)
                self.first_frame_decided = True
                return ("STOP", extra)
            self.first_frame_decided = True
            while body:
                length = CcsdsHeader.from_bytes(body).total_length
                self.queue.append((body[:length], {"vcid": vcid, "protection": "clear"}))
                body = body[length:]
        if self.queue:
            packet, link = self.queue.pop(0)
            return (packet, with_link(extra, link))
        return super().read_data(b"", extra)  # blank-string test: let the next protocol drain


def frame(vcid, *packets):
    return bytes([vcid]) + b"".join(packets)


def build(chunks=(), rules=None, extension_first=True, extension=None):
    store = FakeRulesStore(rules or rules_json([{"id": "allow-all", "action": "ALLOW", "match": {}}]))
    iface = ScriptedInterface(chunks)
    if extension_first:
        ext = iface.add_protocol(FakeLinkProtocol, [], "READ")
    fw = iface.add_protocol(EaglegateFirewallProtocol, PLUGIN_ARGS, "READ")
    if not extension_first:
        ext = iface.add_protocol(FakeLinkProtocol, [], "READ")
    if extension is not None:
        ext.extension = extension
    fw.store = lambda: store
    iface.connect()
    return iface, ext, fw, store


def read_all(iface):
    out = []
    while (packet := iface.read()) is not None:
        out.append(packet)
    return out


def apids(packets):
    return [CcsdsHeader.from_bytes(p.buffer).apid for p in packets]


# ---- collecting extensions ----

class Offers:
    def __init__(self, extension):
        self.extension = extension

    def eaglegate_extension(self):
        return self.extension


def test_collect_finds_only_protocols_that_offer_an_extension():
    found = collect_extensions([object(), Offers(fake_extension())])
    assert list(found) == ["fakelink"] and found["fakelink"].name == "fakelink"


@pytest.mark.parametrize("overrides, message", [
    ({"name": "Bad Name"}, "lower case"),
    ({"section": "rules"}, "core key"),
    ({"parse": None}, "callable"),
    ({"api_versions": (FIREWALL_API_VERSION + 1, FIREWALL_API_VERSION + 2)}, "install matching versions"),
    ({"link_keys": {"vcid": {"type": "float"}}}, "must have a type"),
    ({"link_keys": {"mode": {"type": "enum_list", "values": []}}}, "non-empty list"),
    ({"link_keys": {"vcid": {"type": "int_list", "min": 9, "max": 1}}}, "bad min/max"),
    ({"link_keys": {"Bad-Key": {"type": "int_list"}}}, "not a valid name"),
])
def test_malformed_or_incompatible_extensions_are_refused(overrides, message):
    with pytest.raises(RulesError, match=message):
        collect_extensions([Offers(fake_extension(**overrides))], reserved_sections=TOP_LEVEL_KEYS)


def test_two_extensions_cannot_share_a_section_or_link_key():
    with pytest.raises(RulesError, match="both claim"):
        collect_extensions([Offers(fake_extension()), Offers(fake_extension(name="other"))])
    with pytest.raises(RulesError, match="both define link key 'vcid'"):
        collect_extensions([Offers(fake_extension()), Offers(fake_extension(name="other", section="other"))])


def test_non_extension_object_is_refused():
    with pytest.raises(RulesError, match="not an Extension"):
        collect_extensions([Offers({"name": "x"})])


def test_link_helpers_keep_other_extra_values():
    extra = with_link({"RECEIVED_TIME": 1}, {"vcid": 4})
    assert extra == {"RECEIVED_TIME": 1, LINK_EXTRA_KEY: {"vcid": 4}}
    assert link_of(extra) == {"vcid": 4}
    assert link_of(None) is None and link_of({LINK_EXTRA_KEY: "x"}) is None


# ---- parsing a rules file with an extension section ----

EXTENSIONS = {"fakelink": fake_extension()}


def test_extension_section_is_parsed_and_defaults_apply_when_missing():
    with_section = parse_rules(rules_json([], fakelink={"strict": True}), EXTENSIONS)
    assert with_section.extensions == {"fakelink": {"strict": True}}
    without = parse_rules(rules_json([]), EXTENSIONS)
    assert without.extensions == {"fakelink": {"strict": False}}


def test_extension_section_without_the_extension_is_refused_with_a_hint():
    with pytest.raises(RulesError, match="unknown key.*fakelink.*not on this interface"):
        parse_rules(rules_json([], fakelink={"strict": True}))


def test_unknown_key_lists_the_loaded_extension_sections():
    with pytest.raises(RulesError, match="'fakelink' \\(fakelink\\)"):
        parse_rules(rules_json([], typo=1), EXTENSIONS)


def test_extension_errors_are_rules_errors():
    with pytest.raises(RulesError, match="fakelink must be"):
        parse_rules(rules_json([], fakelink={"strict": "yes"}), EXTENSIONS)

    def crash(raw, where):
        raise KeyError("bug")

    with pytest.raises(RulesError, match="extension 'fakelink' failed to parse 'fakelink'"):
        parse_rules(rules_json([]), {"fakelink": fake_extension(parse=crash)})


def test_extension_section_changes_the_sha256():
    """The section is applied and signed with the rules: one sha256 covers both."""
    a = parse_rules(rules_json([], fakelink={"strict": True}), EXTENSIONS)
    b = parse_rules(rules_json([], fakelink={"strict": False}), EXTENSIONS)
    assert a.sha256 != b.sha256


# ---- link match conditions ----

def link_rule(link, action="ALLOW", rule_id="by-link"):
    return {"id": rule_id, "action": action, "match": {"link": link}}


def test_link_condition_needs_an_extension():
    with pytest.raises(RulesError, match="no extension on this interface provides link information"):
        parse_rules(rules_json([link_rule({"vcid": [1]})]))


@pytest.mark.parametrize("link, message", [
    ({"spi": [1]}, "unknown key"),
    ({"vcid": []}, "non-empty list"),
    ({"vcid": [64]}, "out of range 0..63"),
    ({"vcid": ["x"]}, "not an integer"),
    ({"protection": ["encrypted"]}, "is not one of"),
    ({}, "non-empty object"),
])
def test_bad_link_conditions_are_refused(link, message):
    with pytest.raises(RulesError, match=message):
        parse_rules(rules_json([link_rule(link)]), EXTENSIONS)


def test_link_condition_holds_only_with_matching_link_values():
    ruleset = parse_rules(rules_json([link_rule({"vcid": ["0x04", 5], "protection": ["auth"]})]), EXTENSIONS)
    packet = hk_status()
    assert ruleset.evaluate(packet, link={"vcid": 4, "protection": "auth"}).rule_id == "by-link"
    assert ruleset.evaluate(packet, link={"vcid": 4, "protection": "clear"}).rule_id is None
    assert ruleset.evaluate(packet, link={"vcid": 1, "protection": "auth"}).rule_id is None
    assert ruleset.evaluate(packet, link={"protection": "auth"}).rule_id is None  # key missing
    assert ruleset.evaluate(packet, link=None).rule_id is None  # plain packet interface


def test_link_condition_is_described_in_the_reason():
    match = Match.parse({"apid": [2], "link": {"vcid": [5, 4]}}, "m", LINK_KEYS)
    assert match.summary == "matched APID 0x002; link vcid 4,5"


def test_schema_describes_link_and_settings():
    schema = rules_schema()
    assert schema["match"]["keys"]["link"]["type"] == "link_match"
    assert schema["settings"]["untrust_on_first_packet_reject"]["default"] is True


# ---- settings ----

def test_settings_default_and_parse():
    assert parse_rules(rules_json([])).settings == {"untrust_on_first_packet_reject": True}
    parsed = parse_rules(rules_json([], settings={"untrust_on_first_packet_reject": False}))
    assert parsed.settings == {"untrust_on_first_packet_reject": False}


@pytest.mark.parametrize("settings, message", [
    ({"untrust_on_first_packet_reject": "no"}, "true or false"),
    ({"surprise": True}, "unknown key"),
    ([], "must be an object"),
])
def test_bad_settings_are_refused(settings, message):
    with pytest.raises(RulesError, match=message):
        parse_rules(rules_json([], settings=settings))


# ---- the firewall with an extension in front (real COSMOS read loop) ----

def test_extension_found_and_its_section_loaded_on_connect():
    iface, _, fw, _ = build(rules=rules_json([], fakelink={"strict": True}))
    assert fw.rules_error is None
    assert fw.ruleset.extensions == {"fakelink": {"strict": True}}
    details = iface.details()["read_protocols"][1]["firewall"]
    assert details["api_version"] == FIREWALL_API_VERSION
    assert details["extensions"]["fakelink"]["link_keys"] == LINK_KEYS
    assert details["extensions"]["fakelink"]["layers"] == ["frame"]


def test_extension_after_the_firewall_does_not_count():
    """It would only see packets the firewall already let through."""
    _, _, fw, _ = build(rules=rules_json([], fakelink={"strict": True}), extension_first=False)
    assert fw.ruleset.version == -1 and "unknown key" in fw.rules_error


def test_incompatible_extension_fails_closed():
    _, _, fw, _ = build(extension=fake_extension(api_versions=(99, 99)))
    assert fw.ruleset.version == -1
    assert "install matching versions" in fw.rules_error


def test_several_packets_from_one_frame_all_come_out_without_new_input():
    """The extension queues packets and emits one per call; COSMOS's blank-string
    test must drain the queue before reading the next frame."""
    iface, _, _, _ = build([frame(1, hk_status(), status_3(), ccsds(0x10)), frame(2, ccsds(0x20))])
    packets = read_all(iface)
    assert apids(packets) == [2, 3, 0x10, 0x20]
    assert [p.extra[LINK_EXTRA_KEY]["vcid"] for p in packets] == [1, 1, 1, 2]


def test_rules_can_require_link_values():
    rules = rules_json([link_rule({"vcid": [2]})], default_action="DENY")
    iface, _, fw, store = build([frame(2, hk_status()), frame(1, status_3()), frame(2, ccsds(0x20))], rules=rules)
    assert apids(read_all(iface)) == [2, 0x20]
    assert fw.rejected_by_stage["DEFAULT"] == 1


def test_link_values_are_stored_with_rejected_packets(valkey):
    rules = rules_json([link_rule({"vcid": [2]})], default_action="DENY")
    iface, _, _, _ = build([frame(2, hk_status()), frame(1, status_3())], rules=rules)
    read_all(iface)
    [entry] = valkey.stream("__QUARANTINE__EAGLEGATE_INT")
    assert json.loads(entry["link"]) == {"protection": "clear", "vcid": 1}
    assert entry["apid"] == "0x003" and entry["layer"] == ""


def test_link_rejection_is_counted_quarantined_raw_and_has_no_packet_header(valkey):
    bad = frame(BAD_FRAME, hk_status())
    iface, _, fw, _ = build([frame(1, hk_status()), bad, frame(1, status_3())])
    assert apids(read_all(iface)) == [2, 3]  # a later bad frame affects only itself
    assert fw.rejected_by_stage[LINK] == 1 and not fw.connection_untrusted
    [entry] = valkey.stream("_RAW__EAGLEGATE_INT")
    assert (entry["stage"], entry["layer"], entry["releasable"]) == ("LINK", "frame", "false")
    assert entry["apid"] == "" and entry["bytes"] == bad
    assert entry["reason"].startswith("DENY by link layer 'frame': bad frame")
    assert fw.status_items()["DENIED_LINK"] == 1  # published at most once a second


def test_first_frame_rejected_untrusts_and_discards_with_evidence(valkey):
    iface, _, fw, _ = build([frame(BAD_FRAME), frame(1, hk_status()), frame(1, status_3())])
    assert read_all(iface) == []
    assert fw.connection_untrusted and "first frame was rejected" in fw.untrusted_cause
    assert fw.discarded_bytes == len(frame(1, hk_status())) + len(frame(1, status_3()))
    untrusted = [e for e in valkey.stream("_RAW__EAGLEGATE_INT") if e["stage"] == "UNTRUSTED"]
    assert untrusted and "first frame was rejected" in untrusted[0]["detail"]
    assert valkey.status[-1]["CONNECTION_UNTRUSTED"] == "TRUE"


def test_reconnect_clears_untrusted_state():
    iface, _, fw, _ = build([frame(BAD_FRAME)])
    read_all(iface)
    assert fw.connection_untrusted
    iface.connect()
    assert not fw.connection_untrusted and fw.untrusted_cause is None


# ---- settings.untrust_on_first_packet_reject on a plain packet interface ----

def plain(chunks, settings):
    store = FakeRulesStore(rules_json([{"id": "allow-hk", "action": "ALLOW", "match": {"apid": [2]}}],
                                      settings=settings))
    iface = ScriptedInterface(chunks)
    fw = iface.add_protocol(EaglegateFirewallProtocol, PLUGIN_ARGS, "READ")
    fw.store = lambda: store
    iface.connect()
    return iface, fw, store


def test_first_packet_rejected_untrusts_by_default():
    iface, fw, _ = plain([status_3() + hk_status()], {})
    assert read_all(iface) == []
    assert fw.connection_untrusted and "its first packet was rejected" in fw.untrusted_cause


def test_first_packet_rule_can_be_turned_off():
    iface, fw, _ = plain([status_3() + hk_status()], {"untrust_on_first_packet_reject": False})
    assert apids(read_all(iface)) == [2]
    assert not fw.connection_untrusted and fw.rejected == 1


def test_details_report_settings():
    iface, _, _ = plain([], {"untrust_on_first_packet_reject": False})
    details = iface.details()["read_protocols"][0]["firewall"]
    assert details["settings"] == {"untrust_on_first_packet_reject": False}
    assert details["extensions"] == {}


# ---- interfaces EagleGate cannot be administered on ----

def test_tcp_server_interfaces_are_reported(log):
    from eaglegate_firewall_protocol import interface_warning
    from openc3.interfaces.stream_interface import StreamInterface
    from openc3.interfaces.tcpip_server_interface import TcpipServerInterface

    server = TcpipServerInterface(None, "8011", "10.0", None)
    assert "TCP server interface" in interface_warning(server)
    assert "per-client copy" in interface_warning(StreamInterface())
    assert interface_warning(ScriptedInterface()) is None
    assert interface_warning(None) is None

    store = FakeRulesStore(rules_json([]))
    fw = server.add_protocol(EaglegateFirewallProtocol, PLUGIN_ARGS, "READ")
    fw.store = lambda: store
    fw.connect_reset()
    fw.connect_reset()  # logged once, not on every retry
    assert "TCP server interface" in fw.read_details()["firewall"]["interface_warning"]
    assert sum("TCP server interface" in msg for level, msg in log if level == "ERROR") == 1
