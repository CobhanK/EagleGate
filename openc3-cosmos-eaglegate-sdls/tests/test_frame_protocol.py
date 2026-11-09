"""The SDLS frame protocol in front of the real EagleGate firewall, on a real
openc3 Interface read loop (fake socket, fake bucket and Valkey). No Docker."""
import json
import os
import re

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from conftest import PLUGIN_TXT, ROOT, TLM_TXT, CORE, rules_text, shipped_rules
from eaglegate_ccsds_header import CcsdsHeader
from eaglegate_extensions import LINK_EXTRA_KEY
from eaglegate_firewall_protocol import EaglegateFirewallProtocol
from eaglegate_rules_store import rules_keys
from eaglegate_sdls_frame_protocol import EaglegateSdlsFrameProtocol
from eaglegate_sdls_status import STRING_CHARS, status_items
from eaglegate_test_support import FakeRulesStore, ScriptedInterface, admin_request
from openc3.top_level import get_class_from_module
from openc3.utilities.json import JsonEncoder
from openc3.utilities.string import filename_to_class_name, filename_to_module
from sdls_frames import ASM, FrameBuilder, Layout, idle_packet, packet

SDLS_FILE = "eaglegate_sdls_frame_protocol.py"
SDLS_ARGS = ["enforce", "EAGLEGATE_SDLS"]
FW_ARGS = ["1024", "EAGLEGATE_SDLS/rules/firewall_rules.json"]
IFACE = "EAGLEGATE_SDLS_INT"


def build(chunks=(), rules=None, mode="enforce", firewall=True, connect=True):
    store = FakeRulesStore(rules or rules_text())
    store.keys = rules_keys("DEFAULT", "EAGLEGATE_SDLS")
    iface = ScriptedInterface(chunks)
    iface.name = IFACE
    sdls = iface.add_protocol(EaglegateSdlsFrameProtocol, [mode, "EAGLEGATE_SDLS"], "READ")
    fw = None
    if firewall:
        fw = iface.add_protocol(EaglegateFirewallProtocol, FW_ARGS, "READ")
        fw.store = lambda: store
    if connect:
        iface.connect()
    return iface, sdls, fw, store


def read_all(iface):
    out = []
    while (p := iface.read()) is not None:
        out.append(p)
    return out


def buffers(packets):
    return [p.buffer for p in packets]


def links(packets):
    return [p.extra[LINK_EXTRA_KEY] for p in packets]


def hk(n=0, size=20):
    return packet(0x10 + n, bytes([n]) * size, seq=n)


def clear_vc(*packets_):
    return FrameBuilder(spi=5, vcid=1).add(*packets_)


def auth_vc(*packets_, counter_start=1):
    return FrameBuilder(spi=7, vcid=5, counter_start=counter_start).add(*packets_)


# ---- configuration ----

def test_cosmos_can_load_class_from_filename():
    cls = get_class_from_module(filename_to_module(SDLS_FILE), filename_to_class_name(SDLS_FILE))
    assert cls is EaglegateSdlsFrameProtocol


def test_plugin_txt_wiring():
    with open(PLUGIN_TXT) as f:
        text = f.read()
    substitutions = {"mode": "enforce", "sdls_target_name": "EAGLEGATE_SDLS", "fw_max_length": "1024"}
    rendered = re.sub(r"<%= (\w+) %>", lambda m: substitutions.get(m.group(1), m.group(0)), text)
    protocols = [line.split() for line in rendered.splitlines() if line.strip().startswith("PROTOCOL READ")]
    assert [p[2] for p in protocols] == [SDLS_FILE, "eaglegate_firewall_protocol.py"]  # frames first
    assert protocols[0][3:] == SDLS_ARGS and protocols[1][3:] == FW_ARGS
    assert "MAP_TLM_TARGET <%= core_target_name %> DISABLED" in text
    assert "udp_interface.py" in text and "tcpip_server_interface" not in text.split("INTERFACE")[-1]


def test_bad_mode_is_refused():
    with pytest.raises(ValueError, match="mode must be one of"):
        EaglegateSdlsFrameProtocol("shadow")


def test_extension_is_registered_with_the_firewall():
    iface, _, fw, _ = build()
    assert fw.rules_error is None
    assert fw.ruleset.extensions["link"].scid == 3
    details = iface.details()["read_protocols"][1]["firewall"]
    assert details["extensions"]["link"]["name"] == "sdls"
    assert set(details["extensions"]["link"]["link_keys"]) == {"vcid", "spi", "protection"}


# ---- packets out of frames ----

def test_packets_come_out_with_their_link_values():
    first = hk(1, size=1000)                 # 1006 bytes
    big = packet(0x30, bytes(range(256)) * 3 + bytes(132))  # 906 bytes: crosses into the second frame
    cadus = clear_vc(first, big, hk(2)).cadus()
    assert len(cadus) == 2
    iface, sdls, fw, _ = build(cadus)
    packets = read_all(iface)
    assert buffers(packets) == [first, big, hk(2)]
    assert links(packets)[0] == {"vcid": 1, "spi": 5, "protection": "clear", "frames": 1, "vc_count": 0,
                                 "mc_count": 0}
    assert links(packets)[1]["frames"] == 2 and links(packets)[2]["vc_count"] == 1
    assert fw.rejected == 0
    assert sdls.reassembler.idle_packets == 1  # the filler at the end
    assert sdls.status_items()["PACKETS_OUT"] == 3


@pytest.mark.parametrize("chunk", [1, 7, 100, 1789, 1790, 1791, 5000])
def test_any_tcp_chunking(chunk):
    stream = b"".join(clear_vc(*[hk(i, size=300) for i in range(12)]).cadus())
    chunks = [stream[i:i + chunk] for i in range(0, len(stream), chunk)]
    iface, _, _, _ = build(chunks)
    assert buffers(read_all(iface)) == [hk(i, size=300) for i in range(12)]


def test_authenticated_channel_gives_auth_unverified():
    iface, _, _, _ = build(auth_vc(hk(1), hk(2)).cadus())
    packets = read_all(iface)
    assert buffers(packets) == [hk(1), hk(2)]
    assert {link["protection"] for link in links(packets)} == {"auth_unverified"}
    assert {link["spi"] for link in links(packets)} == {7}


def test_randomized_link_with_fecf():
    rules = rules_text(link_changes={"randomized": True, "has_fecf": True})
    builder = FrameBuilder(spi=5, vcid=1, layout=Layout.for_spi(5, has_fecf=True), randomize=True)
    iface, _, fw, _ = build(builder.add(hk(1)).cadus(), rules=rules)
    assert buffers(read_all(iface)) == [hk(1)] and fw.rejected == 0


# ---- rejected frames ----

def test_first_frame_from_another_spacecraft_untrusts_the_connection(valkey):
    stranger = FrameBuilder(spi=5, vcid=1, scid=99).add(hk(9)).cadus()
    iface, _, fw, _ = build(stranger + clear_vc(hk(1)).cadus())
    assert read_all(iface) == []
    assert fw.connection_untrusted and "its first frame was rejected" in fw.untrusted_cause
    raw = valkey.stream("_RAW__" + IFACE)
    assert (raw[0]["stage"], raw[0]["layer"]) == ("LINK", "frame")
    assert "spacecraft ID 99, expected 3" in raw[0]["reason"]
    assert json.loads(raw[0]["link"])["vcid"] == 1
    assert any(entry["stage"] == "UNTRUSTED" for entry in raw)


def test_first_frame_rule_can_be_turned_off():
    rules = rules_text(link_changes={"untrust_on_first_frame_reject": False})
    stranger = FrameBuilder(spi=5, vcid=1, scid=99).add(hk(9)).cadus()
    iface, _, fw, _ = build(stranger + clear_vc(hk(1)).cadus(), rules=rules)
    assert buffers(read_all(iface)) == [hk(1)] and not fw.connection_untrusted


def test_corrupted_first_frame_does_not_untrust():
    rules = rules_text(link_changes={"has_fecf": True})
    builder = FrameBuilder(spi=5, vcid=1, layout=Layout.for_spi(5, has_fecf=True))
    first, second = builder.add(hk(1), packet(0x40, bytes(2000))).cadus()[:2]
    corrupted = bytearray(first)
    corrupted[200] ^= 0xFF
    later = builder.add(hk(3)).cadus()
    iface, _, fw, _ = build([bytes(corrupted), second] + later, rules=rules)
    assert buffers(read_all(iface)) == [hk(3)]  # the big packet lost its first frame
    assert not fw.connection_untrusted and fw.rejected_by_stage["LINK"] >= 2


def test_downgrade_to_clear_spi_on_the_authenticated_channel(valkey):
    good = auth_vc(hk(1)).cadus()
    downgrade = FrameBuilder(spi=5, vcid=5).add(hk(66)).cadus()  # clear SA on VC 5
    iface, _, fw, _ = build(good + downgrade)
    assert buffers(read_all(iface)) == [hk(1)]
    [entry] = [e for e in valkey.stream("_RAW__" + IFACE) if e["stage"] == "LINK"]
    assert entry["layer"] == "sdls" and "SPI 5 (clear) is not allowed on virtual channel 5" in entry["reason"]
    assert not fw.connection_untrusted  # not the first frame


def test_replayed_frame_is_rejected(valkey):
    builder = auth_vc(hk(1))
    first = builder.cadus()
    second = builder.add(hk(2)).cadus()
    iface, sdls, fw, _ = build(first + second + first)
    assert buffers(read_all(iface)) == [hk(1), hk(2)]
    [entry] = [e for e in valkey.stream("_RAW__" + IFACE) if e["stage"] == "LINK"]
    assert "sequence number 1 is not above the last accepted 2 for SPI 7" in entry["reason"]
    assert sdls.status_items()["REPLAY_REJECTIONS"] == 1 and not fw.connection_untrusted


def test_lost_frame_drops_the_spanning_packet_and_resumes(valkey):
    builder = clear_vc(hk(1, size=1000), *[packet(0x40 + i, bytes(1000)) for i in range(3)], hk(2))
    cadus = builder.cadus()
    assert len(cadus) == 3
    iface, sdls, _, _ = build([cadus[0], cadus[2]])  # the middle frame never arrives
    assert buffers(read_all(iface)) == [hk(1, size=1000), hk(2)]
    reasons = [e["reason"] for e in valkey.stream("_RAW__" + IFACE) if e["layer"] == "reassembly"]
    assert any("frame count gap" in reason for reason in reasons)
    assert sdls.status_items()["VC_COUNT_GAPS"] == 1


def test_bytes_between_frames_are_quarantined(valkey):
    a, b = clear_vc(hk(1)).cadus() + clear_vc(hk(2)).cadus()
    iface, sdls, _, _ = build([a + b"noise" + b])
    assert buffers(read_all(iface)) == [hk(1), hk(2)]
    [entry] = [e for e in valkey.stream("_RAW__" + IFACE) if e["stage"] == "LINK"]
    assert entry["bytes"] == b"noise" and "5 bytes were not part of a frame" in entry["reason"]
    assert sdls.status_items()["SYNC_LOSSES"] == 1


def test_encrypted_channel_is_unreadable_in_phase_1(valkey):
    gcm = FrameBuilder(spi=6, vcid=4).add(hk(1)).cadus()
    iface, sdls, fw, _ = build(clear_vc(hk(0)).cadus() + gcm)
    assert buffers(read_all(iface)) == [hk(0)]
    assert "no crypto backend is configured to decrypt" in fw.last_rejection["reason"]
    assert sdls.status_items()["UNREADABLE_FRAMES"] == 1

    quiet = rules_text(link_changes={"encrypted_without_backend": "drop"})
    valkey.entries.clear()
    iface, sdls, fw, _ = build(clear_vc(hk(0)).cadus() + gcm, rules=quiet)
    read_all(iface)
    assert fw.rejected == 0 and sdls.counts["dropped_quietly"] == 1


# ---- packet rules on link values ----

def test_packet_rules_can_require_protection():
    doc = shipped_rules()
    for rule in doc["rules"]:
        if rule["id"] == "example-no-clear-telemetry":
            rule["enabled"] = True
    iface, _, fw, _ = build(clear_vc(hk(1)).cadus() + auth_vc(hk(2)).cadus(), rules=json.dumps(doc))
    assert buffers(read_all(iface)) == [hk(2)]
    assert fw.last_rejection["rule_id"] == "example-no-clear-telemetry"


# ---- monitor mode ----

def test_monitor_mode_checks_everything_but_passes_nothing(valkey):
    stranger = FrameBuilder(spi=5, vcid=1, scid=99).add(hk(9)).cadus()
    iface, sdls, fw, _ = build(stranger + clear_vc(hk(1), hk(2)).cadus(), mode="monitor")
    assert read_all(iface) == []
    assert not fw.connection_untrusted and sdls.would_untrust
    assert sdls.counts["packets_seen"] == 2 and sdls.counts["packets_out"] == 0
    assert sdls.status_items()["WOULD_UNTRUST"] == "TRUE"


# ---- the rules control the link layer ----

def test_applied_rules_change_the_link_configuration():
    iface, _, fw, store = build()
    iface.chunks = FrameBuilder(spi=5, vcid=1, scid=4).add(hk(1)).cadus()
    assert read_all(iface) == []  # spacecraft 4 is not expected
    store.pending = rules_text(version=2, link_changes={"scid": 4})
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    assert fw.ruleset.version == 2
    iface.connect()  # the first frame made the connection untrusted
    iface.chunks = FrameBuilder(spi=5, vcid=1, scid=4).add(hk(2)).cadus()
    assert buffers(read_all(iface)) == [hk(2)]


def test_invalid_link_section_fails_closed(valkey):
    iface, _, fw, _ = build(clear_vc(hk(1)).cadus() * 2, rules=rules_text(link_changes={"scid": "three"}))
    assert read_all(iface) == []
    assert fw.ruleset.version == -1 and "link.scid" in fw.rules_error
    [entry] = [e for e in valkey.stream("_RAW__" + IFACE) if e["stage"] == "LINK"]
    assert "no link configuration is loaded" in entry["reason"]  # said once, not per frame


def test_rules_without_a_link_section_are_refused():
    doc = shipped_rules()
    del doc["link"]
    _, _, fw, _ = build(rules=json.dumps(doc))
    assert "'link' is required" in fw.rules_error


def test_without_a_firewall_nothing_passes(log):
    iface, sdls, _, _ = build(clear_vc(hk(1)).cadus(), firewall=False)
    assert read_all(iface) == []
    assert "no EagleGate firewall protocol after" in sdls.firewall_error
    assert sum("no EagleGate firewall protocol" in m for level, m in log if level == "ERROR") == 1


def test_incompatible_firewall_api_is_refused(monkeypatch):
    monkeypatch.setattr(EaglegateFirewallProtocol, "EAGLEGATE_FIREWALL_API", 99)
    iface, sdls, fw, _ = build(clear_vc(hk(1)).cadus())
    assert read_all(iface) == []
    assert "provides firewall API 99" in sdls.firewall_error


# ---- anti-replay state and RESET_REPLAY ----

def upload(store, kind="reset_replay", **params):
    text, sha = admin_request(kind=kind, reason="spacecraft rebooted without saved counters", params=params)
    store.requests[kind] = text
    return sha


def test_counters_survive_a_cosmos_restart():
    builder = auth_vc(hk(1))
    first = builder.cadus()
    later = builder.add(hk(2)).cadus()
    iface, _, _, _ = build(first + later)
    assert len(read_all(iface)) == 2
    restarted, _, _, _ = build(first)  # new protocol objects, same Valkey
    assert read_all(restarted) == []


def test_reset_replay_after_the_spacecraft_lost_its_counters(valkey):
    iface, sdls, fw, store = build(auth_vc(hk(1), counter_start=5000).cadus())
    read_all(iface)
    rebooted = auth_vc(hk(2), counter_start=1)
    iface.chunks = rebooted.cadus()
    assert read_all(iface) == []
    assert "possible spacecraft counter loss" in fw.last_rejection["reason"]

    sha = upload(store, spi=7)
    iface.protocol_cmd("RESET_REPLAY", sha, read_write="READ")
    action = fw.admin_actions[-1]
    assert action["ok"] and action["action"] == "RESET_REPLAY" and "relearn" in action["detail"]
    assert action["previous"]["7"]["value"] == "5000"
    iface.chunks = rebooted.add(hk(3)).cadus()
    assert buffers(read_all(iface)) == [hk(3)]
    [audit] = valkey.stream("_AUDIT__" + IFACE)
    assert audit["action"] == "RESET_REPLAY" and audit["spi"] == "7"
    assert sdls.status_items()["REPLAY_RESETS"] == 1


def test_reset_replay_with_a_floor():
    iface, _, fw, store = build(auth_vc(hk(1), counter_start=10).cadus())
    read_all(iface)
    iface.protocol_cmd("RESET_REPLAY", upload(store, spi="all", floor="0x100"), read_write="READ")
    assert fw.admin_actions[-1]["ok"] and fw.admin_actions[-1]["floor"] == 256
    iface.chunks = auth_vc(hk(2), counter_start=200).cadus() + auth_vc(hk(3), counter_start=300).cadus()
    assert buffers(read_all(iface)) == [hk(3)]


@pytest.mark.parametrize("params, message", [
    ({"spi": 5}, "SPI 5 has no anti-replay counter"),
    ({"spi": 99}, "SPI 99 has no anti-replay counter"),
    ({"spi": "seven"}, "spi must be an SPI number"),
    ({"spi": 7, "floor": "lots"}, "floor must be a whole number"),
    ({"spi": 7, "floor": 70000}, "does not fit SPI 7's 2-byte counter"),
    ({"spi": 7, "colour": "red"}, "unknown parameter"),
])
def test_reset_replay_refusals(params, message):
    iface, _, fw, store = build()
    iface.protocol_cmd("RESET_REPLAY", upload(store, **params), read_write="READ")
    action = fw.admin_actions[-1]
    assert action["ok"] is False and message in action["detail"]


def test_reset_replay_needs_an_admin_request():
    iface, _, fw, store = build()
    iface.protocol_cmd("RESET_REPLAY", "0" * 64, read_write="READ")
    assert fw.admin_actions[-1]["ok"] is False and "no reset_replay request" in fw.admin_actions[-1]["detail"]
    upload(store, kind="restore_trust")  # the wrong kind of request
    iface.protocol_cmd("RESET_REPLAY", "0" * 64, read_write="READ")
    assert fw.admin_actions[-1]["ok"] is False


def test_restore_trust_resumes_frames_on_the_same_connection():
    stranger = FrameBuilder(spi=5, vcid=1, scid=99).add(hk(9)).cadus()
    iface, _, fw, store = build(stranger)
    assert read_all(iface) == [] and fw.connection_untrusted
    sha = upload(store, kind="restore_trust")
    iface.protocol_cmd("RESTORE_TRUST", sha, read_write="READ")
    assert not fw.connection_untrusted
    iface.chunks = clear_vc(hk(1)).cadus()
    assert buffers(read_all(iface)) == [hk(1)]


def test_other_protocol_commands_are_not_handled():
    _, sdls, _, _ = build()
    assert sdls.protocol_cmd("SOMETHING") is False


# ---- status packet, details, screens ----

@pytest.fixture
def telemetry():
    from openc3.packets.packet_config import PacketConfig

    config = PacketConfig()
    config.process_file(TLM_TXT, "EAGLEGATE_SDLS")
    return config.telemetry["EAGLEGATE_SDLS"]


def test_link_status_items_fit_the_packet_definition(telemetry):
    packet_def = telemetry["LINK_STATUS"]
    iface, sdls, _, _ = build(clear_vc(hk(1)).cadus())
    read_all(iface)
    items = sdls.status_items()
    items.update({name: "é" * 400 for name in STRING_CHARS})
    for name, value in status_items(items).items():
        packet_def.write(name, value, "CONVERTED")
    for name, chars in STRING_CHARS.items():
        assert packet_def.get_item(name).bit_size == chars * 8, name
    assert set(status_items(items)) == set(packet_def.items) - {
        "SPARE", "PACKET_TIMESECONDS", "PACKET_TIMEFORMATTED", "RECEIVED_TIMESECONDS", "RECEIVED_TIMEFORMATTED",
        "RECEIVED_COUNT"}


def test_firewall_status_definition_is_the_core_one():
    def block(path):
        with open(path) as f:
            text = f.read()
        start = text.index("FIREWALL_STATUS BIG_ENDIAN")
        end = text.find("\nTELEMETRY", start)
        lines = text[start:end if end > 0 else None].splitlines()[1:]
        return [line for line in lines if line.strip() and not line.lstrip().startswith("#")]

    core = os.path.join(CORE, "targets", "EAGLEGATE", "cmd_tlm", "tlm.txt")
    assert block(TLM_TXT) == block(core)


def test_screens_only_show_items_that_exist(telemetry):
    screens = os.path.join(ROOT, "targets", "EAGLEGATE_SDLS", "screens")
    for name in os.listdir(screens):
        with open(os.path.join(screens, name)) as f:
            text = f.read().replace("<%= target_name %>", "EAGLEGATE_SDLS")
        for line in text.splitlines():
            if line.strip().startswith("LABELVALUE"):
                _, target, packet_name, item, *_ = line.split()
                assert target == "EAGLEGATE_SDLS" and item in telemetry[packet_name].items, (name, item)


def test_link_status_is_published(valkey):
    iface, _, _, _ = build(clear_vc(hk(1)).cadus())
    read_all(iface)
    assert valkey.link_status and valkey.link_status[0]["CCSDS_VERSION"] == 6


def test_details_are_plain_json():
    iface, _, _, _ = build(auth_vc(hk(1)).cadus() + FrameBuilder(spi=5, vcid=1, scid=99).add(hk(2)).cadus())
    read_all(iface)
    details = json.loads(json.dumps(iface.details(), cls=JsonEncoder))
    sdls = details["read_protocols"][0]["sdls"]
    assert sdls["config"]["scid"] == 3 and sdls["frames"]["accepted"] == 1
    assert sdls["replay"]["counters"]["7"]["value"] == "1"
    assert sdls["recent"][0]["layer"] == "frame"


def test_idle_only_frames_and_idle_packets_never_reach_the_firewall():
    builder = clear_vc(hk(1))
    cadus = builder.cadus() + [builder.cadu(builder.oid_frame())]
    iface, sdls, fw, _ = build(cadus)
    assert buffers(read_all(iface)) == [hk(1)]
    assert sdls.status_items()["OID_FRAMES"] == 1 and fw.rejected == 0


def test_idle_packets_can_be_kept():
    rules = rules_text(link_changes={"idle": "keep"})
    a, b = hk(1, size=900), hk(2, size=800)  # 1712 bytes: leaves a 54-byte idle filler
    iface, _, _, _ = build(clear_vc(a, b).cadus(), rules=rules)
    packets = buffers(read_all(iface))
    assert packets[:2] == [a, b] and CcsdsHeader.from_bytes(packets[2]).apid == 0x7FF and len(packets[2]) == 54


def test_asm_constant_matches_nos3():
    assert ASM.hex().upper() == shipped_rules()["link"]["asm"] and idle_packet(7)[:2] == b"\x07\xff"


# ---- end to end: any packets, any chunking ----


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(sizes=st.lists(st.integers(1, 1000), min_size=1, max_size=12), chunk=st.integers(1, 4000),
       vc=st.sampled_from([(5, 1), (7, 5)]))
def test_any_packets_through_the_whole_chain(valkey, sizes, chunk, vc):
    valkey.hashes.clear()  # each example is a new spacecraft: no remembered anti-replay counters
    spi, vcid = vc
    originals = [packet(0x10 + i, bytes([i]) * size, seq=i) for i, size in enumerate(sizes)]
    stream = b"".join(FrameBuilder(spi=spi, vcid=vcid).add(*originals).cadus())
    chunks = [stream[i:i + chunk] for i in range(0, len(stream), chunk)]
    iface, _, fw, _ = build(chunks)
    assert buffers(read_all(iface)) == originals
    assert fw.rejected == 0


# ---- through COSMOS's real UDP interface, as plugin.txt configures it ----

def test_real_udp_interface_on_localhost():
    import socket

    from openc3.interfaces.udp_interface import UdpInterface

    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    store = FakeRulesStore(rules_text())
    store.keys = rules_keys("DEFAULT", "EAGLEGATE_SDLS")
    iface = UdpInterface("127.0.0.1", "None", str(port), None, None, 128, 10.0, "2.0", "127.0.0.1")
    iface.name = IFACE
    iface.add_protocol(EaglegateSdlsFrameProtocol, SDLS_ARGS, "READ")
    fw = iface.add_protocol(EaglegateFirewallProtocol, FW_ARGS, "READ")
    fw.store = lambda: store
    try:
        iface.connect()
    except OSError as error:
        pytest.skip(f"no UDP on localhost here: {error}")
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        expected = [hk(i, size=600) for i in range(5)]
        for cadu in clear_vc(*expected).cadus():  # one CADU per datagram, like the NOS3 radio
            sender.sendto(cadu, ("127.0.0.1", port))
        received = []
        while len(received) < len(expected):
            packet_ = iface.read()
            assert packet_ is not None
            received.append(bytes(packet_.buffer))
        assert received == expected
        assert fw.interface_warning is None
    finally:
        sender.close()
        iface.disconnect()
