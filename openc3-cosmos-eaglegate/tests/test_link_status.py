"""The Link status tab's data: traffic counts (eaglegate_traffic.py) for every
packet the firewall judges, and the panels and admin actions an extension
declares for the page (eaglegate_extensions.py, "Panels and actions")."""
import pytest
from hypothesis import given, settings, strategies as st

from conftest import ccsds, hk_status, status_3
from eaglegate_extensions import collect_extensions
from eaglegate_rules_error import RulesError
from eaglegate_traffic import TrafficCounter
from test_extensions import Offers, fake_extension
from test_firewall_protocol import build, read_all

# ---- the counter ----


def counter():
    clock = [1_800_000_000.25]
    return TrafficCounter(clock=lambda: clock[0]), clock


def test_totals_and_per_apid_counts():
    traffic, _ = counter()
    traffic.record(hk_status(seq=1), True)
    traffic.record(ccsds(0x100), False)
    traffic.record(hk_status(seq=2), True)
    doc = traffic.describe()
    assert (doc["packets"], doc["allowed"], doc["rejected"]) == (3, 2, 1)
    assert doc["bytes"] == 2 * len(hk_status()) + len(ccsds(0x100))
    assert doc["bytes_allowed"] == 2 * len(hk_status())
    assert list(doc["apids"]) == ["0x002", "0x100"]  # sorted, hex like the rest of the page
    hk = doc["apids"]["0x002"]
    assert (hk["packets"], hk["allowed"], hk["rejected"], hk["last_seq"]) == (2, 2, 0, 2)
    assert doc["apids"]["0x100"]["rejected"] == 1
    assert doc["last_packet_time"] == "2027-01-15T08:00:00.250000Z" == hk["last_time"]


def test_sequence_gaps_count_the_skipped_packets():
    traffic, _ = counter()
    for seq in (5, 6, 9, 10, 10):  # 7 and 8 lost, then a repeat (counts the full wrap)
        traffic.record(hk_status(seq=seq), True)
    hk = traffic.describe()["apids"]["0x002"]
    assert hk["seq_gaps"] == 2
    assert hk["seq_missing"] == 2 + 16383
    assert traffic.seq_gaps == 2


def test_sequence_count_wraps_without_a_gap():
    traffic, _ = counter()
    for seq in (16382, 16383, 0, 1):
        traffic.record(hk_status(seq=seq), True)
    assert traffic.seq_gaps == 0


def test_each_apid_has_its_own_sequence():
    traffic, _ = counter()
    for packet in (hk_status(seq=1), status_3(seq=40), hk_status(seq=2), status_3(seq=41)):
        traffic.record(packet, True)
    assert traffic.seq_gaps == 0


def test_a_new_connection_starts_sequence_continuity_over():
    traffic, _ = counter()
    traffic.record(hk_status(seq=100), True)
    traffic.new_connection()
    traffic.record(hk_status(seq=3), True)  # a restarted sender
    assert traffic.seq_gaps == 0
    assert traffic.describe()["apids"]["0x002"]["packets"] == 2  # totals are kept


def test_short_data_is_counted_without_an_apid():
    traffic, _ = counter()
    traffic.record(b"\x00\x02", False)
    assert traffic.packets == 1 and traffic.apids == {}


@settings(max_examples=200, deadline=None)
@given(st.lists(st.tuples(st.integers(0, 0x7FF), st.integers(0, 0x3FFF), st.booleans()), max_size=60))
def test_counts_always_add_up(packets):
    traffic, _ = counter()
    for apid, seq, allowed in packets:
        traffic.record(ccsds(apid, seq=seq), allowed)
    doc = traffic.describe()
    assert doc["packets"] == len(packets) == doc["allowed"] + doc["rejected"]
    assert sum(a["packets"] for a in doc["apids"].values()) == len(packets)
    assert sum(a["seq_gaps"] for a in doc["apids"].values()) == doc["seq_gaps"]
    assert len(doc["apids"]) <= 2048


# ---- in the firewall ----

def test_firewall_counts_allowed_and_rejected_packets():
    iface, proto, _ = build([hk_status(seq=1) + ccsds(0x100) + hk_status(seq=3) + status_3()])
    assert len(read_all(iface)) == 3
    traffic = iface.details()["read_protocols"][0]["firewall"]["traffic"]
    assert (traffic["packets"], traffic["allowed"], traffic["rejected"]) == (4, 3, 1)
    assert traffic["apids"]["0x002"]["seq_gaps"] == 1
    items = proto.status_items()
    assert (items["PACKETS"], items["ALLOWED"], items["SEQ_GAPS"]) == (4, 3, 1)


def test_unframed_and_untrusted_bytes_are_not_packets():
    # First packet rejected: the connection is untrusted and the rest is discarded unframed
    iface, proto, _ = build([ccsds(0x100) + hk_status() + hk_status()])
    read_all(iface)
    assert proto.traffic.packets == 1 and proto.traffic.rejected == 1
    assert proto.discarded_bytes == 2 * len(hk_status())


def test_structural_rejections_are_discarded_bytes_not_packets():
    iface, proto, _ = build([hk_status() + ccsds(2, version=3)])
    read_all(iface)
    assert proto.traffic.packets == 1 and proto.rejected_by_stage["STRUCTURAL"] == 1


def test_allowed_traffic_updates_the_status_packet(valkey):
    iface, proto, _ = build([hk_status()])
    proto.status_sent_at = None  # not throttled by the publish at connect
    read_all(iface)
    iface.chunks = [hk_status(seq=1)]
    proto.status_sent_at = None
    # COSMOS calls read_data again after each packet (to drain buffered data), so
    # the update owed for allowed traffic goes out without waiting for a rejection
    read_all(iface)
    assert (valkey.status[-1]["PACKETS"], valkey.status[-1]["ALLOWED"]) == (2, 2)


def test_reconnect_keeps_totals_but_not_sequence_continuity():
    iface, proto, _ = build([hk_status(seq=50)])
    read_all(iface)
    iface.chunks = [hk_status(seq=0)]
    iface.connect()
    read_all(iface)
    assert proto.traffic.packets == 2 and proto.traffic.seq_gaps == 0


# ---- panels and actions an extension declares ----

ACTION = {"name": "reset_thing", "command": "RESET_THING", "title": "Reset",
          "params": {"which": {"type": "string", "required": True}, "floor": {"type": "int"}}}
TABLE = {"title": "Counters", "kind": "table", "path": "state.counters", "key_title": "ID",
         "columns": {"value": "Value"},
         "row_actions": [{"action": "reset_thing", "title": "Reset", "row_param": "which"}],
         "actions": [{"action": "reset_thing", "title": "Reset all", "params": {"which": "all"}}]}
VALUES = {"title": "Frames", "kind": "values", "path": "frames", "items": {"received": "Received"}}


def page_extension(**overrides):
    fields = dict(details_key="fakelink", panels=(VALUES, TABLE), actions=(ACTION,))
    fields.update(overrides)
    return fake_extension(**fields)


def test_panels_and_actions_are_described_for_the_page():
    found = collect_extensions([Offers(page_extension())])
    described = found["fakelink"].describe()
    assert described["details_key"] == "fakelink"
    assert described["panels"] == [VALUES, TABLE] and described["actions"] == [ACTION]


def test_extensions_without_a_page_still_load():
    assert collect_extensions([Offers(fake_extension())])["fakelink"].describe()["panels"] == []


def with_panel(**changes):
    return page_extension(panels=({**TABLE, **changes},))


def with_action(**changes):
    return page_extension(actions=({**ACTION, **changes},), panels=())


@pytest.mark.parametrize("extension, message", [
    (page_extension(details_key="Bad Key"), "details_key must be"),
    (page_extension(details_key=""), "panels need a details_key"),
    (with_action(command="RESTORE_TRUST"), "command of the firewall itself"),
    (with_action(command="reset"), "upper case"),
    (with_action(name="Reset"), "lower case"),
    (with_action(params={"x": {"type": "map"}}), "must have a type"),
    (with_action(params={"bad-name": {"type": "int"}}), "param name"),
    (with_action(surprise=1), "unknown key"),
    (page_extension(actions=(ACTION, ACTION)), "two actions are named"),
    (with_panel(kind="chart"), "kind must be one of"),
    (with_panel(path="../secrets"), "path must be dotted names"),
    (with_panel(title=""), "needs a title"),
    (with_panel(columns={}), "a table needs columns"),
    (with_panel(columns={"value": 3}), "columns must map names to titles"),
    (with_panel(row_actions=[{"action": "nope", "title": "x", "row_param": "which"}]), "not one of"),
    (with_panel(row_actions=[{"action": "reset_thing", "title": "x"}]), "row_param must name"),
    (with_panel(actions=[{"action": "reset_thing", "title": "x", "row_param": "which"}]), "only for row_actions"),
    (with_panel(actions=[{"action": "reset_thing", "title": "x", "params": {"other": 1}}]), "plain values"),
    (with_panel(actions=[{"action": "reset_thing", "title": "x", "params": {"which": [1]}}]), "plain values"),
    (page_extension(panels=({**VALUES, "row_actions": []},)), "for tables"),
])
def test_bad_panels_and_actions_are_refused(extension, message):
    with pytest.raises(RulesError, match=message):
        collect_extensions([Offers(extension)])


def test_two_extensions_cannot_share_an_action_or_command():
    other = page_extension(name="other", section="other", link_keys={}, panels=())
    with pytest.raises(RulesError, match="both define the action"):
        collect_extensions([Offers(page_extension()), Offers(other)])


def test_bad_page_description_keeps_the_rules_from_loading():
    """Like every other extension problem: fail closed, reason in interface_details."""
    from test_extensions import build as build_with_extension
    _, _, fw, _ = build_with_extension(extension=with_panel(kind="chart"))
    assert fw.ruleset.version == -1 and "kind must be one of" in fw.rules_error
