"""SDLS key management in EagleGate (EagleGate/DECISIONS.md, Phase 2 items):
  1 key epochs: anti-replay counters belong to the key that protected them
  2 rekey-due warnings: counter range, not_after, max_frames
  3 counter reuse by a key holder (same counter, other content, both verified)
  7 test keys (reported by the sidecar; see test_sidecar_backend.py)."""
from datetime import datetime, timezone
from types import SimpleNamespace

from conftest import shipped_rules
from eaglegate_sdls_frame_security import VERIFIED, FrameSecurity, SecurityResult
from eaglegate_sdls_keys import KeyWatch, summary_counts
from eaglegate_sdls_link_config import parse_link_config
from eaglegate_sdls_policy import FramePolicy
from eaglegate_sdls_replay import ReplayGuard, ReplayState
from sdls_frames import Layout, build_frame, packet

OLD, NEW = "a130:1111111111111111", "a131:2222222222222222"


def config(**sa7):
    raw = shipped_rules()["link"]
    raw = {**raw, "security_associations": {k: dict(v) for k, v in raw["security_associations"].items()}}
    raw["security_associations"]["7"].update(sa7)
    return parse_link_config(raw)


CONFIG = config()
AUTH = CONFIG.sas[7]


def frame(sn, raw=b"x"):
    return SimpleNamespace(sn_value=sn, iv_value=None, raw=raw)


def accept(guard, value, epoch, raw=b"x", verified=True):
    f = frame(value, raw)
    problem = guard.check(AUTH, f, CONFIG, verified, key_epoch=epoch)
    if problem is None:
        guard.commit(AUTH, f, key_epoch=epoch, counter_verified=verified)
    return problem


# ---- 1: key epochs -------------------------------------------------------------

def test_a_new_key_starts_a_new_baseline():
    guard = ReplayGuard()
    assert accept(guard, 500, OLD) is None
    assert "not above the last accepted" in accept(guard, 3, OLD)  # same key: never back
    assert accept(guard, 3, NEW) is None                           # new key: counters restart
    assert guard.new_keys == 1
    assert (guard.states[7].value, guard.states[7].key, guard.states[7].frames) == (3, NEW, 1)
    assert accept(guard, 2, NEW) is not None                       # NEW never goes back


def test_frames_are_counted_per_key_and_survive_a_restart():
    guard = ReplayGuard()
    for value in (1, 2, 3):
        accept(guard, value, OLD)
    state = ReplayState.from_json(guard.states[7].to_json())
    assert (state.key, state.frames, state.value) == (OLD, 3, 3)
    accept(guard, 1, NEW)
    assert guard.states[7].frames == 1
    legacy = ReplayState.from_json('{"kind": "sn", "value": "9", "floor": null, "updated": ""}')
    assert (legacy.key, legacy.frames) == (None, 0)  # state saved before Phase 2


def test_without_a_known_key_the_old_rules_apply():
    """No epoch (no backend, or a state saved before Phase 2): a counter may
    never go back, whatever the key."""
    guard = ReplayGuard()
    accept(guard, 500, None)
    assert accept(guard, 3, NEW) is not None  # the stored state has no key: stay strict
    accept(guard, 501, NEW)
    assert guard.states[7].key == NEW


def test_reset_keeps_the_key():
    guard = ReplayGuard()
    accept(guard, 500, OLD)
    guard.reset(7, "sn", floor=None)
    assert guard.states[7].key == OLD and accept(guard, 3, OLD) is None


# ---- 3: counter reuse ----------------------------------------------------------

def test_counter_reuse_with_other_content_is_called_out():
    guard = ReplayGuard()
    assert accept(guard, 10, OLD, raw=b"first") is None
    plain_replay = accept(guard, 10, OLD, raw=b"first")
    assert "replay or duplicate" in plain_replay and guard.reuse_count == 0
    reuse = accept(guard, 10, OLD, raw=b"different")
    assert reuse.startswith("COUNTER REUSE") and guard.reuse_count == 1
    assert guard.last_reuse["counter"] == "10"


def test_reuse_needs_a_verified_counter_and_the_same_key():
    guard = ReplayGuard()
    accept(guard, 10, OLD, raw=b"first")
    assert not accept(guard, 10, OLD, raw=b"forged", verified=False).startswith("COUNTER REUSE")
    accept(guard, 11, NEW, raw=b"x")
    assert guard.reuse_count == 0
    unverified = ReplayGuard()
    accept(unverified, 10, OLD, raw=b"first", verified=False)  # its MAC did not cover the counter
    assert not accept(unverified, 10, OLD, raw=b"other").startswith("COUNTER REUSE")


class EpochBackend(FrameSecurity):
    name = "fake"

    def __init__(self, epoch):
        self.epoch = epoch

    def process(self, frame, sa):
        return SecurityResult(VERIFIED, protection="auth", data_field=frame.data_field, key_epoch=self.epoch,
                              counter_verified=True)


def tm(sn, payload=b"A"):
    layout = Layout.for_spi(7)
    data = packet(0x10, payload)
    return build_frame(data + bytes(layout.data_length() - len(data)), 0, spi=7, vcid=5, sn=sn, layout=layout)


def test_policy_counts_reuse_and_new_keys():
    policy = FramePolicy(ReplayGuard())
    backend = EpochBackend(OLD)
    first = policy.check(tm(5, b"A"), CONFIG, backend)
    assert first.accepted and first.key_epoch == OLD and first.counter_verified
    policy.commit(first)
    reused = policy.check(tm(5, b"B"), CONFIG, backend)
    assert not reused.accepted and reused.reuse and not reused.decides_trust
    assert policy.counts["counter_reuse"] == 1 and policy.counts["verified"] == 1
    backend.epoch = NEW
    restarted = policy.check(tm(1, b"C"), CONFIG, backend)
    assert restarted.accepted
    policy.commit(restarted)
    assert policy.replay.new_keys == 1


# ---- 2: due for replacement ----------------------------------------------------

class KeysBackend(FrameSecurity):
    name = "fake"

    def __init__(self, epoch=OLD, test_key=False, mask=True):
        self.epoch, self.test_key, self.mask = epoch, test_key, mask

    def key_epoch(self, spi):
        return self.epoch if spi == 7 else None

    def sa_keys(self):
        return {"7": {"akid": 130, "ekid": None, "fingerprints": "130:1111111111111111", "test_key": self.test_key,
                      "mask_covers_data": self.mask}}


def at(text):
    return lambda: datetime.fromisoformat(text).replace(tzinfo=timezone.utc)


def test_counter_near_the_end_of_its_range():
    guard = ReplayGuard()
    accept(guard, 0xFFFF * 89 // 100, OLD)
    rows = KeyWatch().rows(CONFIG, KeysBackend(), guard)
    assert rows["7"]["due"] is None and rows["7"]["counter_used"] == "89.00%"
    guard = ReplayGuard()
    accept(guard, 0xFFFF * 91 // 100, OLD)
    rows = KeyWatch().rows(CONFIG, KeysBackend(), guard)
    assert "counter at 91.0% of its range" in rows["7"]["due"]
    assert summary_counts(rows) == {"rekey_due": 1, "test_keys": 0}
    # a new key: its counter (and frames) start from zero
    assert KeyWatch().rows(CONFIG, KeysBackend(epoch=NEW), guard)["7"]["due"] is None
    lenient = config()
    object.__setattr__(lenient, "rekey_warn_percent", 95)
    assert KeyWatch().rows(lenient, KeysBackend(), guard)["7"]["due"] is None


def test_not_after_and_max_frames():
    cfg = config(not_after="2027-01-01T00:00:00Z", max_frames=3)
    guard = ReplayGuard()
    for value in (1, 2):
        accept(guard, value, OLD)
    before = KeyWatch(clock=at("2026-12-31T23:59:59")).rows(cfg, KeysBackend(), guard)["7"]
    assert before["due"] is None and before["frames"] == 2
    accept(guard, 3, OLD)
    after = KeyWatch(clock=at("2027-01-01T00:00:00")).rows(cfg, KeysBackend(), guard)["7"]
    assert "past not_after" in after["due"] and "3 frames under this key (max_frames 3)" in after["due"]


def test_each_warning_is_logged_once():
    watch = KeyWatch()
    rows = watch.rows(CONFIG, KeysBackend(test_key=True, mask=False), ReplayGuard())
    first = watch.new_warnings(rows)
    assert {text.split(" ")[0] for _, text in first} == {"uses", "its"}
    assert watch.new_warnings(rows) == []
    assert summary_counts(rows)["test_keys"] == 1


def test_clear_sas_have_no_key_row():
    rows = KeyWatch().rows(CONFIG, None, ReplayGuard())
    assert set(rows) == {"6", "7"} and rows["7"]["fingerprints"] is None
