"""Anti-replay for telemetry: the counter each SA's frames carry must go up.

CryptoLib checks anti-replay only for commands, so EagleGate does it for
telemetry. Per SPI it remembers the last ACCEPTED counter: the sequence number
(ARSN) field, or the IV for GCM SAs whose IV is a counter (SaConfig.replay).

  * a counter at or below the last accepted one is a replay or duplicate;
    far below it (more than max_forward_jump) the reason says the spacecraft
    may have lost its counters, which an admin resolves with RESET_REPLAY
  * a counter that jumps more than max_forward_jump ahead is refused: before
    the Phase 2 crypto backend checks the MAC, the counter is not
    authenticated, and one forged huge value would otherwise lock out every
    real frame after it. A spacecraft that saves its counters in blocks jumps
    ahead by up to one block after a restart; set the limit above that
  * with no remembered counter, replay_baseline decides: "learn" accepts the
    first frame and remembers it, "require" waits for an admin floor

State only changes for frames that were finally accepted (commit), never in
check(), so a frame rejected for any other reason cannot move it. It is kept
in Valkey (ReplayStore), so a COSMOS restart does not reopen the replay window.

Key epochs (SDLS key management): with the sidecar backend each counter belongs
to the key that protected its frames (the key fingerprints, SecurityResult.
key_epoch). Counters restart legitimately when the spacecraft gets a new key,
so a frame under a NEW key starts a new baseline (replay_baseline decides, as
for an SA never seen); under the same key a counter may never go back. The
frames accepted under the current key are counted (max_frames warnings).

Counter reuse: when a frame whose MAC covered its counter repeats a counter
already accepted under the same key, but with different content, the
spacecraft (a key holder) reused an IV/sequence number. For GCM that leaks
the keystream: the rejection says so and is counted separately.
"""
import hashlib
import json
from collections import OrderedDict
from dataclasses import dataclass

from eaglegate_quarantine import _Guarded, utc_now


@dataclass
class ReplayState:
    kind: str                # "sn" or "iv": which counter the value is
    value: int = None        # last accepted counter; None = no baseline yet
    floor: int = None        # an admin's floor: counters below it are refused
    updated: str = ""
    key: str = None          # key epoch the value was counted under (None: unknown, no backend)
    frames: int = 0          # frames accepted under that key

    def to_json(self):
        return json.dumps({"kind": self.kind, "value": _text(self.value), "floor": _text(self.floor),
                           "updated": self.updated, "key": self.key, "frames": self.frames})

    @classmethod
    def from_json(cls, text):
        doc = json.loads(text)
        frames = doc.get("frames", 0)
        return cls(kind=doc["kind"], value=_number(doc.get("value")), floor=_number(doc.get("floor")),
                   updated=doc.get("updated", ""), key=doc.get("key") if isinstance(doc.get("key"), str) else None,
                   frames=frames if isinstance(frames, int) and frames >= 0 else 0)

    def describe(self):
        return {"kind": self.kind, "value": _text(self.value), "floor": _text(self.floor), "updated": self.updated,
                "key": self.key, "frames": self.frames}


def _text(value):
    return None if value is None else str(value)  # counters can exceed JSON's safe integers


def _number(text):
    return None if text in (None, "") else int(text)


RECENT_DIGESTS = 256  # per SPI: counters of recent authenticated frames and what they carried


class ReplayGuard:
    def __init__(self, store=None):
        self.states = {}       # spi -> ReplayState
        self.store = store     # ReplayStore, or None (tests, monitor without Valkey)
        self.rejected = 0
        self.resets = 0
        self.new_keys = 0      # baselines restarted because a new key appeared
        self.reuse_count = 0   # counter reuse by a key holder (see the module docstring)
        self.last_reuse = None
        self.digests = {}      # spi -> (key epoch, OrderedDict counter -> sha256 of the frame)

    def load(self):
        """Read the remembered counters (at connect). Unreadable entries are skipped."""
        if self.store is None:
            return
        for spi, state in self.store.load().items():
            self.states[spi] = state

    def counter(self, sa, frame):
        if sa.replay == "sn":
            return frame.sn_value
        if sa.replay == "iv":
            return frame.iv_value
        return None

    def current(self, sa, key_epoch=None):
        """The state that applies to a frame of this SA under key_epoch (None
        when there is no usable baseline: a new SA, kind or key)."""
        state = self.states.get(sa.spi)
        if state is not None and state.kind != sa.replay:
            return None  # the SA's counter changed kind: the old value means nothing now
        if state is not None and key_epoch is not None and state.key is not None and state.key != key_epoch:
            return None  # a new key: counters start over
        return state

    def check(self, sa, frame, config, verified=False, key_epoch=None):
        """None if the frame's counter is acceptable, else why not. verified:
        the MAC covered the counter (only then can a jump be trusted, or a
        repeat be blamed on a key holder)."""
        if sa.replay == "none":
            return None
        value = self.counter(sa, frame)
        name = "sequence number" if sa.replay == "sn" else "IV"
        state = self.current(sa, key_epoch)
        limit = config.max_jump(sa)
        if state is None or state.value is None:
            floor = state.floor if state else None
            if floor is not None:
                if value < floor:
                    return (f"{name} {value} is below the floor {floor} an admin set for SPI {sa.spi}")
                return None
            if config.replay_baseline == "require":
                return (f"no anti-replay baseline for SPI {sa.spi} yet; an admin must set one "
                        "(Reset counter with a floor) before its frames are accepted")
            return None
        last = state.value
        if value <= last:
            reuse = self._reuse(sa, frame, value, key_epoch) if verified else None
            if reuse:
                return reuse
            if last - value > limit:
                return (f"{name} {value} is far below the last accepted {last} for SPI {sa.spi}: possible "
                        "spacecraft counter loss (after a restart without saved counters); if so, an admin "
                        "can reset the counter. Otherwise a replay of old frames")
            return f"{name} {value} is not above the last accepted {last} for SPI {sa.spi}: a replay or duplicate"
        if value - last > limit and not (verified and config.verified_forward == "any"):
            return (f"{name} {value} jumps {value - last} ahead of the last accepted {last} for SPI {sa.spi} "
                    f"(limit {limit}); refused so a forged counter cannot lock out later frames")
        return None

    def _reuse(self, sa, frame, value, key_epoch):
        epoch, seen = self.digests.get(sa.spi, (None, None))
        if not seen or epoch != key_epoch or value not in seen:
            return None
        if seen[value] == hashlib.sha256(frame.raw).digest():
            return None  # the same frame again: an ordinary replay
        self.reuse_count += 1
        name = "sequence number" if sa.replay == "sn" else "IV"
        self.last_reuse = {"spi": sa.spi, "counter": str(value), "key": key_epoch, "time": utc_now()}
        return (f"COUNTER REUSE: {name} {value} of SPI {sa.spi} was already accepted under the same key with "
                "different content, and both frames' MACs verified: the spacecraft (a key holder) reused a "
                f"{name}. {'For GCM this exposes the keystream. ' if sa.encrypted else ''}Replace the key")

    def commit(self, sa, frame, key_epoch=None, counter_verified=False):
        """Remember the counter of a frame that was finally accepted."""
        if sa.replay == "none":
            return
        state = self.states.get(sa.spi)
        previous = state
        if state is None or state.kind != sa.replay:
            state = ReplayState(kind=sa.replay)
        elif key_epoch is not None and state.key is not None and state.key != key_epoch:
            state = ReplayState(kind=sa.replay)  # the first accepted frame under a new key
            self.new_keys += 1
        self.states[sa.spi] = state
        value = self.counter(sa, frame)
        state.value = value
        state.updated = utc_now()
        if key_epoch is not None:
            state.key = key_epoch
        state.frames = (state.frames if state is previous else 0) + 1
        if counter_verified:
            epoch, seen = self.digests.get(sa.spi, (None, None))
            if seen is None or epoch != key_epoch:
                seen = OrderedDict()
                self.digests[sa.spi] = (key_epoch, seen)
            seen[value] = hashlib.sha256(frame.raw).digest()
            while len(seen) > RECENT_DIGESTS:
                seen.popitem(last=False)
        if self.store is not None:
            self.store.save(sa.spi, state)

    def reset(self, spi, kind, floor=None):
        """RESET_REPLAY: forget the last counter of one SPI (relearn, or start at
        floor). Returns the previous state's description."""
        previous = self.states.get(spi)
        state = ReplayState(kind=kind, value=None, floor=floor, updated=utc_now(),
                            key=previous.key if previous else None)
        self.states[spi] = state
        self.resets += 1
        if self.store is not None:
            self.store.save(spi, state)
        return previous.describe() if previous else None

    def describe(self):
        return {str(spi): state.describe() for spi, state in sorted(self.states.items())}


class ReplayStore(_Guarded):
    """The last accepted counters, in a Valkey hash in COSMOS's persistent store:
      {scope}__EAGLEGATE_SDLS__REPLAY__{interface}   field = SPI, value = ReplayState JSON
    Never raises: a storage problem is counted and must not change a decision."""

    def __init__(self, scope, interface_name):
        super().__init__()
        self.key = f"{scope}__EAGLEGATE_SDLS__REPLAY__{interface_name}"
        self.saved = 0

    def load(self):
        try:
            raw = self._hgetall()
        except Exception as error:
            self._failed(error)
            return {}
        states = {}
        for field_name, text in raw.items():
            try:
                spi = int(field_name.decode() if isinstance(field_name, bytes) else field_name)
                states[spi] = ReplayState.from_json(text.decode() if isinstance(text, bytes) else text)
            except Exception as error:  # one bad entry must not hide the others
                self._failed(error)
        return states

    def save(self, spi, state):
        if self._paused():
            return False
        try:
            self._hset(str(spi), state.to_json())
        except Exception as error:
            self._failed(error)
            return False
        self.saved += 1
        return True

    def summary(self):
        return {"key": self.key, "saved": self.saved, "errors": self.errors, "last_error": self.last_error}

    # ---- COSMOS boundary: separate methods so tests need no Valkey ----------

    def _hgetall(self):
        from openc3.utilities.store import Store

        return Store.hgetall(self.key) or {}

    def _hset(self, field_name, value):
        from openc3.utilities.store import Store

        Store.hset(self.key, field_name, value)
