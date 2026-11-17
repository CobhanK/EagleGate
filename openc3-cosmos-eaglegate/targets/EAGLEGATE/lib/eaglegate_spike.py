"""Spike warning: is the rejection rate suddenly far above normal?

A burst of rejections usually means someone is sending hostile or forged
traffic (or a rule became too strict). This class compares each window of
`spike_window_seconds` with what is normal for this link and raises a state:

  NORMAL    (GREEN)
  ELEVATED  (YELLOW)  COSMOS shows a notification (bell menu)
  SPIKE     (RED)     COSMOS shows an alert toast that must be acknowledged

The state is the FIREWALL_STATUS item SPIKE_STATE, whose STATE colours put it
in COSMOS's own limits system: Telemetry Viewer colours, the Limits Monitor,
limits events, LIMITS_RESPONSE and (Enterprise) Autonomic triggers all work
without EagleGate code (decision C11 in EagleGate/DECISIONS.md).

How a window is judged (standard methods, no invented statistics):
  * baseline: an EWMA of rejections per active window, alpha BASELINE_ALPHA
    (NIST/SEMATECH e-Handbook of Statistical Methods 6.3.2.4, EWMA control
    charts), floored at BASELINE_FLOOR so a quiet link still has a threshold
  * counts are compared with the Poisson distribution of that mean, because
    normal rejection counts are small (0-2 per window) and a Gaussian z-score
    would raise false alarms: P(X >= r) < spike_elevated_p -> ELEVATED,
    < spike_p -> SPIKE
  * spike_ceiling: that many rejections in one window is always a SPIKE,
    whatever the baseline (an attacker cannot teach the baseline a flood)
  * spike_max_fraction: when at least MIN_PACKETS arrived, that share of them
    rejected is at least ELEVATED (normalises for busy passes)
  * spike_critical_count security failures (authenticity or sequence rules,
    SDLS MAC / replay / SPI rejections) in one window are at least ELEVATED
  * a tabular CUSUM (Page 1954; NIST/SEMATECH 6.3.2.3) of the standardised
    counts, k = CUSUM_K, h = CUSUM_H, catches a slow sustained rise
    ("low and slow") before the baseline learns it. It only adds up windows
    the tests above call normal, and restarts when they fire
Windows with no traffic at all (between passes) change nothing. The baseline
does not learn while the state is raised (it cannot be poisoned by the spike
itself). A raised state rises at once and only falls after
spike_clear_windows calmer windows in a row (no flapping, one alert per spike).

Thread safety: the read thread counts, the ticker thread (and the read thread)
close windows; one lock covers both.
"""
import math
import threading
from collections import Counter
from datetime import datetime, timezone

NORMAL, ELEVATED, SPIKE = 0, 1, 2
STATE_NAMES = ("NORMAL", "ELEVATED", "SPIKE")

BASELINE_ALPHA = 0.05   # weight of the newest window: roughly the last 20 active windows
BASELINE_FLOOR = 0.5    # rejections per window assumed normal on a quiet link
CUSUM_K = 0.5           # allowance, in standard deviations
CUSUM_H = 5.0           # decision interval, in standard deviations
MIN_PACKETS = 10        # packets in a window before the rejected fraction counts
RULES_NOTE_WINDOWS = 30  # active windows after a rules change in which a raised state mentions it
CRITICAL_RULE_TYPES = frozenset({"authenticity", "sequence"})
CRITICAL_LAYERS = frozenset({"sdls"})  # the SDLS plugin's security layer (MAC, anti-replay, SPI)

# Rules file settings (settings.<key>), with their defaults. Checked by
# eaglegate_rules_parser.SETTINGS_SCHEMA.
DEFAULTS = {
    "spike_detection": True,
    "spike_window_seconds": 10,
    "spike_ceiling": 100,
    "spike_elevated_p": 0.01,
    "spike_p": 0.0001,
    "spike_max_fraction": 0.5,
    "spike_critical_count": 3,
    "spike_clear_windows": 3,
}


def poisson_tail(count, mean):
    """P(X >= count) for X ~ Poisson(mean). Standard library only."""
    if count <= 0:
        return 1.0
    if mean <= 0:
        return 0.0
    term = math.exp(-mean + count * math.log(mean) - math.lgamma(count + 1))
    total, i = term, count
    while i < count + 100000:
        i += 1
        term *= mean / i
        total += term
        if i > mean and term <= total * 1e-15:
            break
    return min(1.0, total)


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _cause(verdict):
    if verdict.rule_id:
        return verdict.rule_id
    if verdict.layer:
        return f"{verdict.stage.lower()}:{verdict.layer}"
    return verdict.stage.lower()


def is_critical(verdict):
    return verdict.rule_type in CRITICAL_RULE_TYPES or (verdict.stage == "LINK" and verdict.layer in CRITICAL_LAYERS)


class SpikeDetector:
    def __init__(self, clock_text=utc_now):
        self.lock = threading.Lock()
        self.clock_text = clock_text
        self.window_start = None
        self._new_window()
        self.baseline = BASELINE_FLOOR  # rejections per window
        self.cusum = 0.0
        self.state = NORMAL
        self.calm = 0                    # calmer windows in a row while raised
        self.since = ""                  # when the current raised state began
        self.reason = ""
        self.top = ""                    # the rule (or stage) behind most rejections
        self.rate = 0.0                  # rejections per minute in the last closed window
        self.window_seconds = DEFAULTS["spike_window_seconds"]
        self.windows = 0                 # active windows judged
        self.closed = 0                  # windows closed (active or not)
        self.spikes = 0                  # times the state rose from NORMAL
        self.rules_change = None         # (rules version, self.windows when it changed)

    def _new_window(self):
        self.rejected = 0
        self.judged = 0
        self.unjudged = 0  # rejections that were never a judged packet (STRUCTURAL, LINK)
        self.critical = 0
        self.causes = Counter()

    # ---- counting (read thread) ----------------------------------------------

    def packet(self):
        """One packet judged by the rules (allowed or not)."""
        with self.lock:
            self.judged += 1

    def rejection(self, verdict):
        with self.lock:
            self.rejected += 1
            if not verdict.framed:
                self.unjudged += 1
            if is_critical(verdict):
                self.critical += 1
            self.causes[_cause(verdict)] += 1

    # ---- judging -------------------------------------------------------------

    def tick(self, settings, now):
        """Close every window that has ended by `now` (monotonic seconds).
        Returns (old_state, new_state) when the state changed, else None."""
        settings = {**DEFAULTS, **(settings or {})}
        width = float(settings["spike_window_seconds"])
        with self.lock:
            self.window_seconds = width
            if self.window_start is None:
                self.window_start = now
                return None
            if now - self.window_start < width:
                return None
            old = self.state
            elapsed = int((now - self.window_start) // width)
            self.closed += 1
            self._close(settings, width)
            # Whole windows that passed with no data at all: calm, but learn nothing
            for _ in range(min(elapsed - 1, int(settings["spike_clear_windows"]))):
                self._settle(NORMAL, settings, "no traffic")
            self.window_start += elapsed * width
            return (old, self.state) if self.state != old else None

    def _close(self, settings, width):
        r, total = self.rejected, self.judged + self.unjudged
        critical, causes = self.critical, self.causes
        self._new_window()
        self.rate = r * 60.0 / width
        if not settings["spike_detection"]:
            self._settle(NORMAL, settings, "spike detection is off", force=True)
            return
        if r == 0 and total == 0:
            self._settle(NORMAL, settings, "no traffic")
            return
        self.windows += 1
        mean = max(self.baseline, BASELINE_FLOOR)
        tail = poisson_tail(r, mean)
        level, why = NORMAL, []
        if r >= settings["spike_ceiling"]:
            level = SPIKE
            why.append(f"at or above the ceiling of {settings['spike_ceiling']}")
        elif tail < settings["spike_p"]:
            level = SPIKE
            why.append(f"P={tail:.1e} for a normal window")
        elif tail < settings["spike_elevated_p"]:
            level = ELEVATED
            why.append(f"P={tail:.1e} for a normal window")
        if total >= MIN_PACKETS and r / total >= settings["spike_max_fraction"]:
            level = max(level, ELEVATED)
            why.append(f"{100 * r / total:.0f}% of {total} packets rejected")
        if critical >= settings["spike_critical_count"]:
            level = max(level, ELEVATED)
            why.append(f"{critical} security failures (authenticity, sequence or SDLS)")
        if level == NORMAL:
            # CUSUM looks only for what the tests above miss: a rise too small for any
            # one window. A window they flag restarts it, so a big burst cannot keep
            # the warning up after the traffic is back to normal
            self.cusum = max(0.0, self.cusum + (r - mean) / math.sqrt(mean) - CUSUM_K)
            if self.cusum > CUSUM_H:
                level = ELEVATED
                why.append("a sustained rise (CUSUM)")
        else:
            self.cusum = 0.0
        if level != NORMAL and self.rules_change and self.windows - self.rules_change[1] <= RULES_NOTE_WINDOWS:
            why.append(f"the rules changed to version {self.rules_change[0]} "
                       f"{self.windows - self.rules_change[1]} windows ago (a rule may be too strict)")
        top = ""
        if causes:
            name, count = causes.most_common(1)[0]
            top = name
            why.append(f"mostly {name} ({count})")
        summary = f"{r} rejections in {width:g} s, normal {mean:.1f}"
        self._settle(level, settings, "; ".join([summary, *why]), top=top)
        if self.state == NORMAL and level == NORMAL:
            self.baseline = BASELINE_ALPHA * r + (1 - BASELINE_ALPHA) * self.baseline

    def _settle(self, level, settings, reason, top="", force=False):
        """Rise at once; fall only after spike_clear_windows calmer windows."""
        if level > self.state:
            if self.state == NORMAL:
                self.spikes += 1
                self.since = self.clock_text()
            self.state, self.calm, self.reason, self.top = level, 0, reason, top
        elif level < self.state:
            self.calm += 1
            if force or self.calm >= settings["spike_clear_windows"]:
                self.state, self.calm = level, 0
                self.reason = reason if level != NORMAL else f"back to normal ({reason})"
                self.top = top if level != NORMAL else ""
                if level == NORMAL:
                    self.since = ""
                    self.cusum = 0.0  # restart after a signal, as the CUSUM procedure does
        else:
            self.calm = 0
            if level != NORMAL:
                self.reason, self.top = reason, top or self.top

    def rules_changed(self, version):
        """New rules: what was normal before says nothing about them. Start from the
        strict floor (more warnings, never fewer) and mention the change for a while."""
        with self.lock:
            self.baseline = BASELINE_FLOOR
            self.cusum = 0.0
            self.rules_change = (version, self.windows)

    # ---- reporting -----------------------------------------------------------

    def status(self):
        """FIREWALL_STATUS items."""
        with self.lock:
            per_minute = 60.0 / self.window_seconds
            return {
                "SPIKE_STATE": STATE_NAMES[self.state],  # a state name, like CONNECTION_UNTRUSTED
                "REJECT_RATE": round(self.rate, 3),
                "REJECT_BASELINE": round(max(self.baseline, BASELINE_FLOOR) * per_minute, 3),
                "SPIKE_REASON": self.reason,
                "SPIKE_TOP_RULE": self.top,
                "SPIKE_SINCE": self.since,
            }

    def describe(self):
        """For interface_details()."""
        with self.lock:
            return {
                "state": STATE_NAMES[self.state],
                "since": self.since or None,
                "reason": self.reason,
                "top": self.top,
                "rate_per_minute": round(self.rate, 3),
                "baseline_per_window": round(self.baseline, 4),
                "window_seconds": self.window_seconds,
                "cusum": round(self.cusum, 3),
                "windows": self.windows,
                "spikes": self.spikes,
            }
