"""The "link" section of the rules file (eaglegate_sdls_link_config)."""
import copy

import pytest

from conftest import shipped_rules
from eaglegate_rules_error import RulesError
from eaglegate_sdls_link_config import (_SA_KEYS, _TOP_KEYS, LINK_KEYS, LINK_SCHEMA, PROTECTIONS, SA_SCHEMA,
                                        parse_link_config)

SHIPPED = shipped_rules()["link"]


def link(**changes):
    raw = copy.deepcopy(SHIPPED)
    raw.update(changes)
    return raw


def test_shipped_nos3_link_section():
    config = parse_link_config(SHIPPED)
    assert (config.scid, config.frame_length, config.asm.hex(), config.cadu_length) == (3, 1786, "1acffc1d", 1790)
    assert config.vcs == {1: frozenset({5}), 4: frozenset({6}), 5: frozenset({7})}
    clear, enc, auth = config.sas[5], config.sas[6], config.sas[7]
    assert (clear.mode, clear.iv_len, clear.replay, clear.authenticated, clear.encrypted) == \
        ("clear", 12, "none", False, False)
    assert (enc.mode, enc.iv_len, enc.replay, enc.encrypted) == ("enc", 12, "iv", True)
    assert (auth.mode, auth.sn_len, auth.mac_len, auth.replay, auth.authenticated) == ("auth", 2, 16, "sn", True)
    assert config.crypto.backend == "none"
    assert config.max_jump(auth) == 1000


def test_minimal_section_takes_defaults():
    config = parse_link_config({"scid": 1, "frame_length": 256, "security_associations": {"1": {"mode": "clear"}},
                                "virtual_channels": {"0": {"spi": [1]}}})
    assert (config.asm.hex(), config.randomized, config.has_fecf, config.has_ocf) == ("1acffc1d", False, False, False)
    assert (config.unverified_auth, config.encrypted_without_backend, config.frame_counter_gap) == \
        ("allow", "deny", "warn")
    assert (config.replay_baseline, config.verified_forward, config.idle) == ("learn", "limit", "drop")
    assert config.untrust_on_first_frame_reject is True


def test_section_is_required():
    with pytest.raises(RulesError, match="'link' is required"):
        parse_link_config(None)


@pytest.mark.parametrize("changes, message", [
    ({"surprise": 1}, "unknown key"),
    ({"scid": 1024}, "out of range"),
    ({"frame_length": 8}, "out of range"),
    ({"frame_type": "AOS"}, "must be one of"),
    ({"asm": "XYZ"}, "not hex"),
    ({"asm": "00" * 9}, "at most 8 bytes"),
    ({"randomized": "no"}, "true or false"),
    ({"security_associations": {}}, "non-empty object"),
    ({"security_associations": {"5": {"mode": "clear"}, "0x5": {"mode": "clear"}}}, "SPI 5 twice"),
    ({"security_associations": {"5": {"mode": "weird"}}}, "must be one of"),
    ({"security_associations": {"5": {"iv_len": 12}}}, "needs 'mode'"),
    ({"security_associations": {"5": {"mode": "clear", "mac_len": 16}}}, "mac_len must be 0"),
    ({"security_associations": {"5": {"mode": "auth"}}}, "mac_len above 0"),
    ({"security_associations": {"5": {"mode": "clear", "replay": "sn"}}}, "sn_len above 0"),
    ({"security_associations": {"5": {"mode": "clear", "replay": "iv"}}}, "iv_len above 0"),
    ({"security_associations": {"5": {"mode": "clear", "sn_len": 17}}}, "out of range"),
    ({"security_associations": {"5": {"mode": "clear", "max_forward_jump": 0}}}, "out of range"),
    ({"security_associations": {"5": {"mode": "clear", "keys": "no"}}}, "unknown key"),
    ({"virtual_channels": {"8": {"spi": [5]}}}, "out of range"),
    ({"virtual_channels": {"1": {"spi": []}}}, "non-empty list"),
    ({"virtual_channels": {"1": {"spi": [9]}}}, "SPI 9 is not in security_associations"),
    ({"virtual_channels": {"1": {"spi": [5], "mode": "x"}}}, "unknown key"),
    ({"virtual_channels": {"1": {"spi": [5]}, "0x1": {"spi": [5]}}}, "VCID 1 twice"),
    ({"unverified_auth": "maybe"}, "must be one of"),
    ({"crypto": {"backend": "cloud"}}, "must be one of"),
    ({"crypto": {"backend": "none", "hots": "x"}}, "unknown key"),
    ({"crypto": {"backend": "sidecar", "host": "evil host; rm"}}, "host name"),
    ({"crypto": {"backend": "sidecar", "port": 0}}, "out of range"),
    ({"crypto": {"backend": "sidecar", "timeout_ms": 5}}, "out of range"),
    ({"crypto": {"backend": "sidecar", "key_id": "a b"}}, "key_id"),
    ({"crypto": {"backend": "sidecar", "on_unavailable": "allow"}}, "must be one of"),
    ({"crypto": {"backend": "sidecar", "test_keys": "ignore"}}, "must be one of"),
    ({"security_associations": {"5": {"mode": "clear", "ekid": 3}}}, "ekid is for encrypting SAs"),
    ({"security_associations": {"5": {"mode": "clear"}, "6": {"mode": "enc", "iv_len": 12, "akid": 3}}},
     "akid is for authenticating SAs"),
    ({"security_associations": {"5": {"mode": "clear", "not_after": "next tuesday"}}}, "UTC time"),
    ({"security_associations": {"5": {"mode": "clear", "not_after": "2027-01-01T00:00:00"}}}, "UTC time"),
    ({"security_associations": {"5": {"mode": "clear", "max_frames": 0}}}, "out of range"),
    ({"rekey_warn_percent": 0}, "out of range"),
    ({"rekey_warn_percent": 101}, "out of range"),
    ({"max_forward_jump": 0}, "out of range"),
])
def test_bad_sections_are_refused(changes, message):
    with pytest.raises(RulesError, match=message):
        parse_link_config(link(**changes))


@pytest.mark.parametrize("key", ["scid", "frame_length", "security_associations", "virtual_channels"])
def test_required_keys(key):
    raw = link()
    del raw[key]
    with pytest.raises(RulesError, match=f"needs '{key}'"):
        parse_link_config(raw)


def test_every_allowed_sa_must_leave_room_for_data():
    with pytest.raises(RulesError, match="leave no room for data"):
        parse_link_config(link(frame_length=40, security_associations={"5": {"mode": "auth", "mac_len": 32}},
                               virtual_channels={"1": {"spi": [5]}}))
    # an SA no virtual channel uses is not checked
    parse_link_config(link(frame_length=40, security_associations={"5": {"mode": "clear"}, "6": {
        "mode": "auth", "mac_len": 64}}, virtual_channels={"1": {"spi": [5]}}))


def test_empty_asm_means_no_sync_marker():
    assert parse_link_config(link(asm="")).asm == b""


def test_replay_kind_defaults():
    sas = parse_link_config(link(security_associations={
        "1": {"mode": "auth", "sn_len": 4, "mac_len": 16},
        "2": {"mode": "authenc", "iv_len": 12, "mac_len": 16},
        "3": {"mode": "auth", "mac_len": 16},
        "4": {"mode": "auth", "sn_len": 4, "mac_len": 16, "replay": "none"},
    }, virtual_channels={"1": {"spi": [1, 2, 3, 4]}})).sas
    assert [sas[s].replay for s in (1, 2, 3, 4)] == ["sn", "iv", "none", "none"]


def test_schema_describes_exactly_what_the_parser_accepts():
    assert set(LINK_SCHEMA["fields"]) == _TOP_KEYS
    assert set(SA_SCHEMA["fields"]) == _SA_KEYS
    assert LINK_KEYS["protection"]["values"] == list(PROTECTIONS)
    assert set(LINK_SCHEMA["fields"]["crypto"]["fields"]) == {"backend", "host", "port", "timeout_ms", "key_id",
                                                              "on_unavailable", "test_keys"}


def test_sidecar_and_key_management_settings():
    raw = link(crypto={"backend": "sidecar", "host": "sidecar.local", "port": 7711, "timeout_ms": 200,
                       "key_id": "k-2026", "on_unavailable": "unverified", "test_keys": "deny"},
               rekey_warn_percent=75)
    raw["security_associations"]["7"].update(akid=130, not_after="2027-06-30T00:00:00Z", max_frames=1000000)
    raw["security_associations"]["6"].update(ekid=9, not_after="2027-06-30")
    config = parse_link_config(raw)
    crypto = config.crypto
    assert (crypto.backend, crypto.host, crypto.port, crypto.timeout_ms, crypto.key_id, crypto.on_unavailable,
            crypto.test_keys) == ("sidecar", "sidecar.local", 7711, 200, "k-2026", "unverified", "deny")
    assert config.rekey_warn_percent == 75
    auth, enc = config.sas[7], config.sas[6]
    assert (auth.akid, auth.ekid, auth.max_frames, auth.not_after_time().year) == (130, None, 1000000, 2027)
    assert (enc.ekid, enc.not_after_time().month) == (9, 6)
    assert auth.counter_width() == 2 and enc.counter_width() == 12 and config.sas[5].counter_width() == 0
    defaults = parse_link_config(link(crypto={"backend": "sidecar"})).crypto
    assert (defaults.host, defaults.port, defaults.timeout_ms, defaults.on_unavailable, defaults.test_keys) == \
        ("eaglegate-sdls-sidecar", 7710, 500, "deny", "warn")
