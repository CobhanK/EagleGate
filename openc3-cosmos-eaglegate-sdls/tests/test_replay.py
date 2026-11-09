"""Telemetry anti-replay (eaglegate_sdls_replay)."""
import json
from types import SimpleNamespace

import pytest

from conftest import shipped_rules
from eaglegate_sdls_link_config import SaConfig, parse_link_config
from eaglegate_sdls_replay import ReplayGuard, ReplayState, ReplayStore

AUTH = SaConfig(spi=7, mode="auth", sn_len=2, mac_len=16, replay="sn")
GCM = SaConfig(spi=6, mode="enc", iv_len=12, replay="iv")
CONFIG = parse_link_config(shipped_rules()["link"])  # max_forward_jump 1000, learn


def frame(sn=None, iv=None):
    return SimpleNamespace(sn_value=sn, iv_value=iv)


def config(**changes):
    raw = {**shipped_rules()["link"], **changes}
    return parse_link_config(raw)


def accept(guard, sa, value, cfg=CONFIG, verified=False):
    f = frame(sn=value) if sa.replay == "sn" else frame(iv=value)
    problem = guard.check(sa, f, cfg, verified)
    if problem is None:
        guard.commit(sa, f)
    return problem


def test_counter_must_increase():
    guard = ReplayGuard()
    assert accept(guard, AUTH, 10) is None          # learned
    assert accept(guard, AUTH, 11) is None
    assert "not above the last accepted 11" in accept(guard, AUTH, 11)
    assert "replay or duplicate" in accept(guard, AUTH, 5)
    assert accept(guard, AUTH, 12) is None


def test_far_below_hints_at_counter_loss():
    guard = ReplayGuard()
    accept(guard, AUTH, 5000)
    problem = accept(guard, AUTH, 3)
    assert "far below the last accepted 5000" in problem and "possible spacecraft counter loss" in problem


def test_jump_ahead_is_limited():
    guard = ReplayGuard()
    accept(guard, AUTH, 10)
    assert accept(guard, AUTH, 1010) is None
    problem = accept(guard, AUTH, 2011)
    assert "jumps 1001 ahead" in problem and "(limit 1000)" in problem


def test_per_sa_limit_overrides_the_link_limit():
    sa = SaConfig(spi=7, mode="auth", sn_len=2, mac_len=16, replay="sn", max_forward_jump=5)
    guard = ReplayGuard()
    accept(guard, sa, 1)
    assert accept(guard, sa, 7) and accept(guard, sa, 6) is None


def test_verified_frames_may_jump_when_configured():
    guard = ReplayGuard()
    accept(guard, AUTH, 1)
    assert accept(guard, AUTH, 50000, verified=True)  # "limit" is the default
    assert accept(guard, AUTH, 50000, cfg=config(verified_forward="any"), verified=False)
    assert accept(guard, AUTH, 50000, cfg=config(verified_forward="any"), verified=True) is None


def test_require_baseline_waits_for_an_admin_floor():
    guard = ReplayGuard()
    strict = config(replay_baseline="require")
    assert "no anti-replay baseline for SPI 7" in accept(guard, AUTH, 100, strict)
    guard.reset(7, "sn", floor=200)
    assert "below the floor 200" in accept(guard, AUTH, 100, strict)
    assert accept(guard, AUTH, 200, strict) is None
    assert "not above" in accept(guard, AUTH, 200, strict)


def test_reset_relearns():
    guard = ReplayGuard()
    accept(guard, AUTH, 5000)
    previous = guard.reset(7, "sn")
    assert previous["value"] == "5000" and guard.resets == 1
    assert accept(guard, AUTH, 3) is None


def test_iv_counters_for_gcm():
    guard = ReplayGuard()
    assert accept(guard, GCM, 2**90) is None
    assert "IV" in accept(guard, GCM, 2**90)
    assert accept(guard, GCM, 2**90 + 1) is None


def test_check_never_changes_state():
    guard = ReplayGuard()
    accept(guard, AUTH, 10)
    guard.check(AUTH, frame(sn=11), CONFIG)
    guard.check(AUTH, frame(sn=999999), CONFIG)
    assert guard.states[7].value == 10


def test_sa_without_replay_is_never_checked():
    none = SaConfig(spi=5, mode="clear", iv_len=12)
    guard = ReplayGuard()
    assert guard.check(none, frame(iv=1), CONFIG) is None
    guard.commit(none, frame(iv=1))
    assert guard.states == {}


def test_changing_counter_kind_forgets_the_old_value():
    guard = ReplayGuard()
    accept(guard, AUTH, 50)
    as_iv = SaConfig(spi=7, mode="authenc", iv_len=12, mac_len=16, replay="iv")
    assert accept(guard, as_iv, 1) is None
    assert guard.states[7].kind == "iv"


# ---- persistence ----

def test_counters_survive_a_restart(valkey):
    store = ReplayStore("DEFAULT", "SDLS_INT")
    guard = ReplayGuard(store)
    accept(guard, AUTH, 2**100)
    guard.reset(6, "iv", floor=7)
    restarted = ReplayGuard(ReplayStore("DEFAULT", "SDLS_INT"))
    restarted.load()
    assert restarted.states[7].value == 2**100 and restarted.states[6].floor == 7
    assert "not above" in accept(restarted, AUTH, 2**100)
    stored = valkey.hashes["DEFAULT__EAGLEGATE_SDLS__REPLAY__SDLS_INT"]
    assert json.loads(stored["7"])["value"] == str(2**100)  # text: beyond JSON's safe integers


def test_store_failures_never_raise(valkey):
    store = ReplayStore("DEFAULT", "SDLS_INT")
    guard = ReplayGuard(store)
    valkey.fail = True
    assert accept(guard, AUTH, 1) is None        # still decided in memory
    assert store.errors == 1 and "valkey down" in store.last_error
    assert store.save(7, guard.states[7]) is False  # paused after the failure
    guard.load()  # unreadable store: nothing loaded, no exception


def test_bad_stored_entries_are_skipped(valkey):
    valkey.hashes["DEFAULT__EAGLEGATE_SDLS__REPLAY__SDLS_INT"] = {
        "7": ReplayState(kind="sn", value=9).to_json(), "x": "{}", "6": "not json"}
    store = ReplayStore("DEFAULT", "SDLS_INT")
    states = store.load()
    assert list(states) == [7] and states[7].value == 9 and store.errors == 2


@pytest.mark.parametrize("value", [None, 0, 2**128 - 1])
def test_state_json_round_trip(value):
    state = ReplayState(kind="iv", value=value, floor=value, updated="t")
    assert ReplayState.from_json(state.to_json()) == state
