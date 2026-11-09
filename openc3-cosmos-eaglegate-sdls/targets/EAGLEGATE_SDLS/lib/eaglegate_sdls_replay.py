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
"""
import json
from dataclasses import dataclass

from eaglegate_quarantine import _Guarded, utc_now


@dataclass
class ReplayState:
    kind: str                # "sn" or "iv": which counter the value is
    value: int = None        # last accepted counter; None = no baseline yet
    floor: int = None        # an admin's floor: counters below it are refused
    updated: str = ""

    def to_json(self):
        return json.dumps({"kind": self.kind, "value": _text(self.value), "floor": _text(self.floor),
                           "updated": self.updated})

    @classmethod
    def from_json(cls, text):
        doc = json.loads(text)
        return cls(kind=doc["kind"], value=_number(doc.get("value")), floor=_number(doc.get("floor")),
                   updated=doc.get("updated", ""))

    def describe(self):
        return {"kind": self.kind, "value": _text(self.value), "floor": _text(self.floor), "updated": self.updated}


def _text(value):
    return None if value is None else str(value)  # counters can exceed JSON's safe integers


def _number(text):
    return None if text in (None, "") else int(text)


class ReplayGuard:
    def __init__(self, store=None):
        self.states = {}       # spi -> ReplayState
        self.store = store     # ReplayStore, or None (tests, monitor without Valkey)
        self.rejected = 0
        self.resets = 0

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

    def check(self, sa, frame, config, verified=False):
        """None if the frame's counter is acceptable, else why not."""
        if sa.replay == "none":
            return None
        value = self.counter(sa, frame)
        name = "sequence number" if sa.replay == "sn" else "IV"
        state = self.states.get(sa.spi)
        if state is not None and state.kind != sa.replay:
            state = None  # the SA's counter changed kind: the old value means nothing now
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
            if last - value > limit:
                return (f"{name} {value} is far below the last accepted {last} for SPI {sa.spi}: possible "
                        "spacecraft counter loss (after a restart without saved counters); if so, an admin "
                        "can reset the counter. Otherwise a replay of old frames")
            return f"{name} {value} is not above the last accepted {last} for SPI {sa.spi}: a replay or duplicate"
        if value - last > limit and not (verified and config.verified_forward == "any"):
            return (f"{name} {value} jumps {value - last} ahead of the last accepted {last} for SPI {sa.spi} "
                    f"(limit {limit}); refused so a forged counter cannot lock out later frames")
        return None

    def commit(self, sa, frame):
        """Remember the counter of a frame that was finally accepted."""
        if sa.replay == "none":
            return
        state = self.states.get(sa.spi)
        if state is None or state.kind != sa.replay:
            state = ReplayState(kind=sa.replay)
            self.states[sa.spi] = state
        state.value = self.counter(sa, frame)
        state.updated = utc_now()
        if self.store is not None:
            self.store.save(sa.spi, state)

    def reset(self, spi, kind, floor=None):
        """RESET_REPLAY: forget the last counter of one SPI (relearn, or start at
        floor). Returns the previous state's description."""
        previous = self.states.get(spi)
        state = ReplayState(kind=kind, value=None, floor=floor, updated=utc_now())
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
