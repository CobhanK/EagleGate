"""Firewall protocol tests: real openc3 Interface + LengthProtocol code,
fake TCP connection and fake rules storage. No Docker."""
import pytest
from hypothesis import settings, given, strategies as st

from conftest import (HK_STATUS_LENGTH, PLUGIN_TXT, STATUS_3_LENGTH, ccsds, hk_status,
                      rules_json, shipped_rules_text, status_3)
from eaglegate_firewall_protocol import EaglegateFirewallProtocol
from eaglegate_ccsds_header import CcsdsHeader
from eaglegate_rules_store import rules_keys
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
    """Stands in for eaglegate_rules_store.RulesStore (the COSMOS config bucket).

    original: the plugin's rules/firewall_rules.json
    active:   rules_active.json (only the firewall writes it)
    pending:  rules_pending.json (what an admin uploads); `text` is an alias,
              so a test sets store.text and then sends RELOAD_RULES"""

    def __init__(self, original):
        self.original = original
        self.active = None
        self.active_signature = None  # the HMAC stored as metadata on the active object
        self.pending = None
        self.saved = []           # (version, sha256) of every save_active
        self.fail_save = False    # make save_active fail, like a bucket outage
        self.keys = rules_keys("DEFAULT", "EAGLEGATE")
        self.last_error = None

    @property
    def text(self):
        return self.pending

    @text.setter
    def text(self, value):
        self.pending = value

    def read_original(self):
        return self.original

    def read_active(self):
        return self.active, self.active_signature

    def read_pending(self):
        return self.pending

    def save_active(self, text, version, sha256, signature=None):
        if self.fail_save:
            self.last_error = "ConnectionError: bucket down"
            return False
        self.active = text
        self.active_signature = signature
        self.saved.append((version, sha256))
        return True


def build(chunks=(), rules=None, connect=True):
    store = FakeRulesStore(shipped_rules_text() if rules is None else rules)
    iface = ScriptedInterface(chunks)
    proto = iface.add_protocol(EaglegateFirewallProtocol, PLUGIN_ARGS, "READ")
    proto.store = lambda: store
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
    iface, proto, _ = build([hk_status()], rules=None, connect=False)
    proto.store().original = None
    iface.connect()
    assert read_all(iface) == []
    assert "no rules found" in proto.rules_error


def test_reconnect_with_broken_file_keeps_last_known_good():
    """Interfaces reconnect after link drops; a broken file then must not open
    (or close) the firewall. The protocol object, and its rules, survive reconnects."""
    iface, proto, store = build([hk_status()])
    store.original = "{broken"  # e.g. a bad plugin upgrade
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
    proto.apply_pending()
    assert proto.rules_error
    store.text = rules_json([], version=5)
    proto.apply_pending()
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
    proto.apply_pending()
    store.text = shipped_rules_text()
    assert proto.apply_pending()
    assert proto.ruleset is running and proto.rules_error is None


# ---- pending / active rules (the rules editor's two-phase apply) ----

V2_ALLOW_ALL = rules_json([{"id": "allow-all", "action": "ALLOW", "match": {}}], version=2)


def test_valid_pending_becomes_running_and_startup_set():
    iface, proto, store = build()
    store.pending = V2_ALLOW_ALL
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    assert proto.ruleset.version == 2 and proto.rules_source == "pending"
    assert store.active == V2_ALLOW_ALL and store.saved == [(2, proto.ruleset.sha256)]


def test_invalid_pending_never_becomes_the_startup_set():
    """Otherwise a restart would load it, fail, and deny everything."""
    iface, proto, store = build()
    store.pending = "{broken"
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    assert proto.rules_error and store.active is None and store.saved == []
    iface.connect()  # restart
    assert proto.ruleset.version == 1 and proto.rules_source == "original"


def test_startup_prefers_active_and_never_loads_pending():
    iface, proto, store = build(connect=False)
    store.active = rules_json([], version=4)
    store.pending = V2_ALLOW_ALL  # uploaded but never applied
    iface.connect()
    assert proto.ruleset.version == 4 and proto.rules_source == "active"


def test_startup_without_active_uses_plugin_original():
    _, proto, _ = build()
    assert proto.ruleset.version == 1 and proto.rules_source == "original"


def test_reload_without_pending_rereads_startup_set():
    iface, proto, store = build()
    store.active = rules_json([], version=6)
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    assert proto.ruleset.version == 6 and proto.rules_source == "active"


def test_stale_base_sha256_is_refused():
    """Two admins edit version 1; the second apply must not silently undo the first."""
    iface, proto, store = build()
    v1 = proto.ruleset.sha256
    store.pending = V2_ALLOW_ALL
    iface.protocol_cmd("RELOAD_RULES", v1, read_write="READ")
    assert proto.ruleset.version == 2
    store.pending = rules_json([], version=2)  # the other admin, still based on v1
    iface.protocol_cmd("RELOAD_RULES", v1, read_write="READ")
    assert proto.ruleset.version == 2 and "changed by someone else" in proto.rules_error
    assert store.active == V2_ALLOW_ALL


def test_pending_sha256_mismatch_is_refused():
    iface, proto, store = build()
    store.pending = V2_ALLOW_ALL
    iface.protocol_cmd("RELOAD_RULES", proto.ruleset.sha256, "0" * 64, read_write="READ")
    assert proto.ruleset.version == 1 and "pending rules file changed" in proto.rules_error


def test_unset_arguments_from_the_command_line_are_ignored():
    iface, proto, store = build()
    store.pending = V2_ALLOW_ALL
    iface.protocol_cmd("RELOAD_RULES", "None", "", read_write="READ")
    assert proto.ruleset.version == 2 and proto.rules_error is None


def test_reapplying_running_rules_keeps_state_and_saves_active():
    """Applying the plugin original unchanged makes it the saved startup set
    without resetting what the sequence and rate rules remember."""
    iface, proto, store = build()
    running = proto.ruleset
    store.pending = shipped_rules_text()
    iface.protocol_cmd("RELOAD_RULES", running.sha256, running.sha256, read_write="READ")
    assert proto.ruleset is running and store.active == shipped_rules_text()


def test_failed_save_still_applies_but_reports_persist_error(log):
    iface, proto, store = build()
    store.fail_save = True
    store.pending = V2_ALLOW_ALL
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    assert proto.ruleset.version == 2
    fw = iface.details()["read_protocols"][0]["firewall"]
    assert "could not save" in fw["persist_error"] and "bucket down" in fw["persist_error"]
    assert any(level == "ERROR" and "could not save" in msg for level, msg in log)


def test_details_name_the_rule_keys_and_source():
    iface, _, _ = build()
    fw = iface.details()["read_protocols"][0]["firewall"]
    assert fw["rules_keys"]["pending"] == "DEFAULT/eaglegate/EAGLEGATE/rules_pending.json"
    assert fw["rules_source"] == "original" and fw["persist_error"] is None


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
