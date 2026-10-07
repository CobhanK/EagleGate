"""Firewall protocol tests: real openc3 Interface + LengthProtocol code,
fake TCP connection and fake rules storage. No Docker."""
import pytest
from hypothesis import settings, given, strategies as st

from conftest import (HK_STATUS_LENGTH, PLUGIN_TXT, STATUS_3_LENGTH, ccsds, hk_status,
                      rules_json, shipped_rules_text, status_3)
from eaglegate_firewall_protocol import EaglegateFirewallProtocol
from eaglegate_ccsds_header import CcsdsHeader
from openc3.interfaces.interface import Interface
from openc3.top_level import get_class_from_module
from openc3.utilities.string import filename_to_class_name, filename_to_module

# Exactly the strings plugin.txt passes after ERB substitution
PLUGIN_ARGS = ["1024", "EAGLEGATE/rules/firewall_rules.json"]
PROTOCOL_FILE = "eaglegate_firewall_protocol.py"


class ScriptedInterface(Interface):
    """Stands in for TCP: returns scripted chunks, then asks to disconnect."""

    def __init__(self, chunks=()):
        super().__init__()
        self.chunks = list(chunks)
        self.name = "EAGLEGATE_INT"

    def connected(self):
        return True

    def read_interface(self):
        if not self.chunks:
            return (None, None)
        data = self.chunks.pop(0)
        self.read_interface_base(data, None)
        return (data, None)


class FakeRulesStore:
    """Stands in for the COSMOS config bucket."""

    def __init__(self, text):
        self.text = text

    def read(self):
        if self.text is None:
            raise FileNotFoundError("rules file not found")
        return self.text


def build(chunks=(), rules=None, connect=True):
    store = FakeRulesStore(shipped_rules_text() if rules is None else rules)
    iface = ScriptedInterface(chunks)
    proto = iface.add_protocol(EaglegateFirewallProtocol, PLUGIN_ARGS, "READ")
    proto.read_rules_text = store.read
    if connect:
        iface.connect()  # COSMOS calls connect_reset() on every protocol here
    return iface, proto, store


def read_all(iface):
    out = []
    while (p := iface.read()) is not None:
        out.append(p.buffer)
    return out


def apids(packets):
    return [CcsdsHeader.from_bytes(p).apid for p in packets]


# ---- configuration ----

def test_cosmos_can_load_class_from_filename():
    cls = get_class_from_module(filename_to_module(PROTOCOL_FILE), filename_to_class_name(PROTOCOL_FILE))
    assert cls is EaglegateFirewallProtocol


def test_plugin_txt_protocol_line_matches_this_class():
    """plugin.txt must name this file and pass exactly the arguments the tests use."""
    with open(PLUGIN_TXT) as f:
        line = next(l for l in f if l.strip().startswith("PROTOCOL READ"))
    line = line.replace("<%= fw_max_length %>", "1024").replace("<%= eaglegate_target_name %>", "EAGLEGATE")
    words = line.split()
    assert words[2] == PROTOCOL_FILE
    assert words[3:] == PLUGIN_ARGS


def test_reads_rules_through_cosmos_target_file(monkeypatch):
    """The real loader asks TargetFile for the configured path (modified copy first)."""
    calls = []

    class FakeTargetFile:
        @staticmethod
        def body(scope, name):
            calls.append((scope, name))
            return shipped_rules_text()

    import openc3.utilities.target_file as tf
    monkeypatch.setattr(tf, "TargetFile", FakeTargetFile)
    proto = EaglegateFirewallProtocol(*PLUGIN_ARGS, "TESTSCOPE")
    assert proto.load_rules()
    assert calls == [("TESTSCOPE", "EAGLEGATE/rules/firewall_rules.json")]


# ---- rules loaded on connect ----

def test_rules_loaded_on_connect():
    iface, proto, _ = build([hk_status() + ccsds(0x100) + status_3()])
    assert proto.ruleset.version == 1
    assert apids(read_all(iface)) == [2, 3]


def test_no_valid_rules_at_startup_denies_everything(log):
    iface, proto, _ = build([hk_status() + status_3()], rules="{broken")
    assert read_all(iface) == []
    assert proto.ruleset.version == -1
    assert any(level == "ERROR" and "DENY ALL" in msg for level, msg in log)


def test_missing_rules_file_at_startup_denies_everything():
    iface, proto, _ = build([hk_status()], connect=False)
    proto.read_rules_text = FakeRulesStore(None).read
    iface.connect()
    assert read_all(iface) == []


def test_reconnect_with_broken_file_keeps_last_known_good():
    """Interfaces reconnect after link drops; a broken file then must not open
    (or close) the firewall. The protocol object, and its rules, survive reconnects."""
    iface, proto, store = build([hk_status()])
    store.text = None  # file deleted / unreadable
    iface.connect()
    assert proto.ruleset.version == 1
    assert apids(read_all(iface)) == [2]


# ---- hot reload ----

def test_reload_swaps_rules_while_streaming():
    iface, proto, store = build([hk_status(), ccsds(0x100)], connect=True)
    assert apids([iface.read().buffer]) == [2]
    store.text = rules_json([{"id": "allow-all", "action": "ALLOW", "match": {}}], version=2)
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")  # what interface_protocol_cmd triggers
    assert apids(read_all(iface)) == [0x100]  # was denied under v1
    assert proto.ruleset.version == 2


def test_invalid_reload_keeps_last_known_good(log):
    iface, proto, store = build([hk_status(), status_3()])
    store.text = rules_json([{"id": "x", "action": "ALLOW", "match": {"apids": [1]}}], version=2)  # typo
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    assert proto.ruleset.version == 1
    assert "unknown key" in proto.rules_error
    assert apids(read_all(iface)) == [2, 3]  # still filtering with v1


def test_successful_reload_clears_error():
    iface, proto, store = build()
    store.text = "{broken"
    proto.load_rules()
    assert proto.rules_error
    store.text = rules_json([], version=5)
    proto.load_rules()
    assert proto.rules_error is None and proto.ruleset.version == 5


def test_unknown_protocol_cmd_not_handled():
    _, proto, _ = build()
    assert proto.protocol_cmd("SOMETHING_ELSE") is False


def test_details_report_active_rules_and_counters():
    iface, proto, _ = build([hk_status() + ccsds(0x100)])
    read_all(iface)
    fw = iface.details()["read_protocols"][0]["firewall"]
    assert fw["rules"]["version"] == 1
    assert fw["rules"]["sha256"] == proto.ruleset.sha256
    assert fw["rules"]["rule_hits"]["allow-hk-status"] == 1
    assert fw["rules"]["default_hits"] == 1
    assert fw["rejected"] == 1 and fw["rules_error"] is None


def test_reject_log_names_the_rule(log):
    iface, _, _ = build([ccsds(2, packet_type=1) + status_3()])
    read_all(iface)
    assert any("rejected APID 0x002: DENY by rule 'deny-commands-on-tlm-link': matched type CMD (rules v1)"
               in m for _, m in log)


# ---- structural floor cannot be disabled by rules ----

ALLOW_ALL = rules_json([{"id": "allow-all", "action": "ALLOW", "match": {}}], version=9)


def test_hostile_length_rejected_even_with_allow_all_rules():
    iface, _, _ = build([hk_status(), ccsds(2, b"", length_field=0xFFFF), status_3()], rules=ALLOW_ALL)
    assert apids(read_all(iface)) == [2, 3]


def test_bad_version_rejected_even_with_allow_all_rules():
    garbage = ccsds(2, version=5) + hk_status()
    iface, proto, _ = build([hk_status(), garbage, status_3()], rules=ALLOW_ALL)
    assert apids(read_all(iface)) == [2, 3]
    assert proto.discarded_bytes == len(garbage)


# ---- no delay behind denied packets ----

def test_many_denied_packets_do_not_delay_the_next_allowed_one():
    stream = status_3() + b"".join(ccsds(0x10 + i) for i in range(50)) + hk_status()
    iface, proto, _ = build([stream])
    assert apids(read_all(iface)) == [3, 2]
    assert proto.rejected == 50


# ---- a rejected first packet makes the whole connection untrusted ----

def test_rejected_first_packet_denies_rest_of_connection(log):
    first = ccsds(0x100)  # not allowed by the shipped rules
    iface, proto, _ = build([first + hk_status(), status_3()])  # same chunk, then a later one
    assert read_all(iface) == []
    assert proto.connection_untrusted
    assert proto.rejected == 1  # later packets are discarded as bytes, not judged
    assert proto.discarded_bytes == len(hk_status()) + len(status_3())
    assert iface.details()["read_protocols"][0]["firewall"]["connection_untrusted"] is True
    assert sum("until the interface reconnects" in m for _, m in log) == 1  # logged once


def test_malformed_first_packet_denies_rest_of_connection():
    iface, proto, _ = build([ccsds(2, version=5), hk_status(), status_3()], rules=ALLOW_ALL)
    assert read_all(iface) == []
    assert proto.connection_untrusted


def test_reconnect_clears_untrusted_connection():
    iface, proto, _ = build([ccsds(0x100), hk_status()])
    assert read_all(iface) == []
    iface.chunks = [hk_status(), status_3()]
    iface.connect()  # COSMOS reconnecting after the link drops
    assert not proto.connection_untrusted
    assert apids(read_all(iface)) == [2, 3]


def test_broken_rules_at_startup_stay_untrusted_until_reconnect():
    """Fixing the rules does not reopen the connection: the bytes dropped while
    untrusted were never framed, so only a reconnect gives a clean start."""
    iface, proto, store = build([hk_status()], rules="{broken")
    assert read_all(iface) == []
    store.text = ALLOW_ALL
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    iface.chunks = [hk_status()]
    assert read_all(iface) == [] and proto.connection_untrusted
    iface.chunks = [hk_status()]
    iface.connect()
    assert apids(read_all(iface)) == [2]


def test_rejection_after_allowed_first_packet_only_affects_that_packet():
    iface, proto, _ = build([hk_status() + ccsds(0x100) + status_3()])
    assert apids(read_all(iface)) == [2, 3]
    assert not proto.connection_untrusted


# ---- rule errors and stateful rules inside the protocol ----

def test_error_while_evaluating_denies_packet_and_keeps_running(log):
    """An exception must deny the packet, never disconnect COSMOS or let it through."""
    iface, proto, _ = build([hk_status() + hk_status() + status_3()])
    real_evaluate = proto.ruleset.evaluate
    calls = []

    def evaluate_failing_on_second_packet(packet):
        calls.append(packet)
        if len(calls) == 2:
            raise RuntimeError("boom")
        return real_evaluate(packet)

    proto.ruleset.evaluate = evaluate_failing_on_second_packet
    assert apids(read_all(iface)) == [2, 3]  # the second packet is dropped, nothing else
    assert any("DENY by error: rules engine error: boom" in m for _, m in log)


SEQUENCE_RULES = rules_json([
    {"id": "in-order", "type": "sequence", "action": "DENY", "match": {}},
    {"id": "allow-all", "action": "ALLOW", "match": {}},
])


def test_reconnect_keeps_replay_protection():
    """Reconnecting reloads the same rules file; that must not reset sequence memory."""
    stream = ccsds(2, seq=5) + ccsds(2, seq=6)
    iface, proto, _ = build([stream[:5], stream[5:]], rules=SEQUENCE_RULES)  # split mid-packet
    assert [CcsdsHeader.from_bytes(p).seq_count for p in read_all(iface)] == [5, 6]
    iface.chunks = [ccsds(2, seq=7), ccsds(2, seq=6)]  # next packet, then a replay
    iface.connect()
    assert [CcsdsHeader.from_bytes(p).seq_count for p in read_all(iface)] == [7]
    assert proto.ruleset.rules[0].hits == 1


def test_changed_rules_file_starts_sequence_memory_fresh():
    """After the spacecraft resets its counters, applying a changed file recovers."""
    iface, proto, store = build([ccsds(2, seq=100)], rules=SEQUENCE_RULES)
    read_all(iface)
    store.text = SEQUENCE_RULES.replace('"version": 1', '"version": 2')
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    iface.chunks = [ccsds(2, seq=0)]  # counters restarted at 0
    assert len(read_all(iface)) == 1


def test_unchanged_reload_keeps_rule_set_and_clears_old_error():
    _, proto, store = build()
    running = proto.ruleset
    store.text = "{broken"
    proto.load_rules()
    store.text = shipped_rules_text()
    assert proto.load_rules()
    assert proto.ruleset is running and proto.rules_error is None


def test_missing_file_in_cosmos_storage_is_a_rules_error(monkeypatch):
    class EmptyTargetFile:
        @staticmethod
        def body(scope, name):
            return None

    import openc3.utilities.target_file as tf
    monkeypatch.setattr(tf, "TargetFile", EmptyTargetFile)
    proto = EaglegateFirewallProtocol(*PLUGIN_ARGS, "TESTSCOPE")
    assert not proto.load_rules()
    assert "RulesError" in proto.rules_error and "not found" in proto.rules_error


# ---- fuzz ----

@settings(max_examples=300, deadline=None)
@given(st.lists(st.binary(min_size=1, max_size=200), min_size=1, max_size=6))
def test_fuzz_random_chunks_never_crash_or_leak(chunks):
    # A valid first packet keeps the connection trusted, so the random bytes
    # reach the framing and rules instead of just being discarded
    iface, _, _ = build([hk_status()] + chunks)
    for pkt in read_all(iface):  # any exception here would disconnect COSMOS
        h = CcsdsHeader.from_bytes(pkt)
        assert h.version == 0 and h.packet_type == 0
        assert len(pkt) == h.total_length == ALLOWED_LENGTH[h.apid]


ALLOWED_LENGTH = {2: HK_STATUS_LENGTH, 3: STATUS_3_LENGTH}  # what the shipped rules allow


@settings(max_examples=200, deadline=None)
@given(st.lists(st.tuples(st.sampled_from([2, 3, 0x100]), st.binary(min_size=3, max_size=6)),
                min_size=1, max_size=10),
       st.integers(min_value=1, max_value=40))
def test_fuzz_valid_streams_any_chunking(packets, chunk_size):
    """Payloads of 3..6 bytes mix correctly sized housekeeping packets with wrong ones."""
    packets = [ccsds(apid, payload) for apid, payload in packets]
    stream = b"".join(packets)
    chunks = [stream[i:i + chunk_size] for i in range(0, len(stream), chunk_size)]
    iface, _, _ = build(chunks)
    allowed = [p for p in packets if len(p) == ALLOWED_LENGTH.get(CcsdsHeader.from_bytes(p).apid)]
    first_allowed = allowed[:1] == packets[:1]  # a rejected first packet blocks the connection
    assert read_all(iface) == (allowed if first_allowed else [])
