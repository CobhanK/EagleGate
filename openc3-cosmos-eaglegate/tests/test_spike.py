"""Spike warning (eaglegate_spike.py, decision C11): a jump in rejections
raises SPIKE_STATE, which COSMOS's limits system turns into a notification
(YELLOW) or an alert (RED)."""
import math

import pytest
from conftest import ccsds, hk_status, rules_json
from eaglegate_spike import (
    BASELINE_FLOOR,
    DEFAULTS,
    ELEVATED,
    NORMAL,
    SPIKE,
    SpikeDetector,
    is_critical,
    poisson_tail,
)
from eaglegate_verdict import LINK, RULE, STRUCTURAL, Verdict
from test_firewall_protocol import build, read_all

W = DEFAULTS["spike_window_seconds"]


def deny(rule_id="deny-x", rule_type="match", stage=RULE, layer=""):
    return Verdict(action="DENY", stage=stage, rule_id=rule_id if stage == RULE else None,
                   rule_type=rule_type if stage == RULE else None, layer=layer, detail="d", rules_version=1)


class Run:
    """Drives a detector window by window."""

    def __init__(self, **settings):
        self.detector = SpikeDetector(clock_text=lambda: "2026-11-16T12:00:00Z")
        self.settings = {**DEFAULTS, **settings}
        self.now = 0.0
        self.detector.tick(self.settings, self.now)  # opens the first window

    def window(self, rejected=0, packets=None, verdict=None):
        """One window: `packets` judged (default: as many as rejected), `rejected` of them denied."""
        packets = rejected if packets is None else packets
        for _ in range(packets):
            self.detector.packet()
        for _ in range(rejected):
            self.detector.rejection(verdict or deny())
        self.now += self.settings["spike_window_seconds"]
        return self.detector.tick(self.settings, self.now)

    @property
    def state(self):
        return self.detector.state


# ---- the statistics ----------------------------------------------------------------

def test_poisson_tail():
    assert poisson_tail(0, 0.5) == 1.0
    assert poisson_tail(1, 0.5) == pytest.approx(1 - math.exp(-0.5))
    assert poisson_tail(4, 0.5) == pytest.approx(1 - math.exp(-0.5) * (1 + 0.5 + 0.125 + 0.5 ** 3 / 6))
    assert poisson_tail(3, 10.0) == pytest.approx(1 - math.exp(-10) * (1 + 10 + 50))
    assert 0 < poisson_tail(500, 0.5) < 1e-300 or poisson_tail(500, 0.5) == 0.0  # no overflow
    assert poisson_tail(5, 0) == 0.0


def test_security_failures_are_critical():
    assert is_critical(deny(rule_type="authenticity"))
    assert is_critical(deny(rule_type="sequence"))
    assert is_critical(deny(stage=LINK, layer="sdls"))  # SDLS MAC, anti-replay, SPI
    assert not is_critical(deny(rule_type="range"))
    assert not is_critical(deny(stage=LINK, layer="frame"))


# ---- behaviour ---------------------------------------------------------------------

def test_a_quiet_link_stays_normal():
    run = Run()
    for rejected in [0, 1, 0, 2, 0, 1, 0, 0, 1, 1] * 5:
        assert run.window(rejected, packets=20) is None
    assert run.state == NORMAL


def test_a_sudden_flood_is_a_spike_that_clears_after_calm_windows():
    run = Run()
    for _ in range(10):
        run.window(0, packets=20)
    assert run.window(25, packets=30, verdict=deny("auth-hk", "authenticity")) == (NORMAL, SPIKE)
    info = run.detector.describe()
    assert info["state"] == "SPIKE" and info["since"] == "2026-11-16T12:00:00Z" and info["top"] == "auth-hk"
    assert info["reason"].startswith("25 rejections in 10 s, normal 0.5")
    assert "mostly auth-hk (25)" in info["reason"] and "security failures" in info["reason"]
    assert run.detector.status()["REJECT_RATE"] == 150.0  # per minute
    assert run.window(0, packets=20) is None and run.window(0, packets=20) is None  # still raised
    assert run.window(0, packets=20) == (SPIKE, NORMAL)
    assert run.detector.describe()["reason"].startswith("back to normal") and run.detector.since == ""
    assert run.detector.spikes == 1


def test_the_baseline_does_not_learn_from_the_spike():
    run = Run()
    for _ in range(5):
        run.window(40, packets=40)
    assert run.state == SPIKE and run.detector.baseline == BASELINE_FLOOR


def test_the_ceiling_is_a_spike_whatever_is_normal():
    run = Run(spike_ceiling=30)
    run.detector.baseline = 40.0  # a link where 40 per window is normal
    assert run.window(30, packets=100) == (NORMAL, SPIKE)
    assert "ceiling of 30" in run.detector.reason


def test_a_high_rejected_fraction_is_elevated():
    run = Run()
    run.detector.baseline = 6.0
    assert run.window(6, packets=10) == (NORMAL, ELEVATED)
    assert "60% of 10 packets rejected" in run.detector.reason
    run2 = Run()
    run2.detector.baseline = 6.0
    assert run2.window(6, packets=9) is None  # too few packets to judge a fraction


def test_a_few_security_failures_are_elevated():
    run = Run()
    run.detector.baseline = 5.0
    assert run.window(3, packets=100, verdict=deny(stage=LINK, layer="sdls")) == (NORMAL, ELEVATED)
    assert "3 security failures" in run.detector.reason and run.detector.top == "link:sdls"


def test_a_slow_rise_is_caught_by_cusum():
    run = Run()
    run.detector.baseline = 2.0
    states = [run.window(4, packets=100) for _ in range(20)]
    assert (NORMAL, ELEVATED) in states
    assert "CUSUM" in run.detector.reason


def test_windows_without_traffic_teach_nothing_and_let_a_spike_clear():
    run = Run()
    run.window(30)
    assert run.state == SPIKE
    baseline = run.detector.baseline
    run.now += 1000  # the pass ended: nothing at all for a long time
    assert run.detector.tick(run.settings, run.now) == (SPIKE, NORMAL)
    assert run.detector.baseline == baseline


def test_turning_detection_off_clears_at_once():
    run = Run()
    run.window(30)
    run.settings["spike_detection"] = False
    assert run.window(30) == (SPIKE, NORMAL)
    assert run.window(300) is None


def test_new_rules_restart_strict_and_are_mentioned():
    run = Run()
    run.detector.baseline = 20.0
    run.detector.rules_changed(7)
    assert run.detector.baseline == BASELINE_FLOOR
    run.window(1, packets=10)
    run.window(15, packets=20)
    assert run.state == SPIKE and "rules changed to version 7 2 windows ago" in run.detector.reason


def test_unjudged_rejections_count_towards_the_fraction():
    run = Run()
    run.detector.baseline = 8.0
    # 8 garbage buffers (never framed) and 2 good packets: 80% rejected
    assert run.window(8, packets=2, verdict=deny(stage=STRUCTURAL)) == (NORMAL, ELEVATED)
    assert "80% of 10 packets" in run.detector.reason


# ---- in the firewall ---------------------------------------------------------------

class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def clocked(rules):
    clock = Clock()
    iface, fw, _ = build(rules=rules, connect=False)
    fw.clock = clock
    iface.connect()  # opens the first spike window at 0
    return iface, fw, clock


def test_the_firewall_raises_the_alarm(valkey, log):
    iface, fw, clock = clocked(rules_json([{"id": "allow-hk", "action": "ALLOW", "match": {"apid": [2]}}]))
    iface.chunks = [hk_status()] + [ccsds(5)] * 40
    read_all(iface)
    clock.now = W
    assert fw.tick_spike() is True
    items = fw.status_items()
    assert items["SPIKE_STATE"] == "SPIKE" and items["SPIKE_TOP_RULE"] == "default" and items["REJECT_RATE"] == 240.0
    assert items["SPIKE_REASON"].startswith("40 rejections in 10 s")
    # A notification with the reason; COSMOS raises the alert itself from SPIKE_STATE
    [(level, text, kind)] = [m for m in log if len(m) == 3]
    assert (level, kind) == ("ERROR", "notification") and "rejections SPIKE: 40 rejections" in text
    [audit] = valkey.stream("_AUDIT__EAGLEGATE_INT")
    assert (audit["action"], audit["state"], audit["previous_state"]) == ("SPIKE", "SPIKE", "NORMAL")
    assert iface.details()["read_protocols"][0]["firewall"]["spike"]["state"] == "SPIKE"
    for step in (2, 3, 4):
        clock.now = step * W
        changed = fw.tick_spike()
    assert changed is True and fw.status_items()["SPIKE_STATE"] == "NORMAL"
    assert log[-1][0] == "WARN" and "spike normal: back to normal" in log[-1][1]


def test_a_spike_forces_a_status_packet(valkey):
    _, fw, clock = clocked(rules_json([]))
    fw.status_sent_at = 10 ** 12  # just published: normally throttled
    for _ in range(40):
        fw.spike.rejection(deny())
    clock.now = W
    before = len(valkey.status)
    fw._publish_status_if_due()
    assert len(valkey.status) == before + 1 and valkey.status[-1]["SPIKE_STATE"] == "SPIKE"


def test_the_ticker_publishes_while_the_link_is_silent(valkey, monkeypatch):
    import eaglegate_firewall_protocol

    monkeypatch.setattr(eaglegate_firewall_protocol, "TICK_SECONDS", 0.01)
    iface, fw, _ = build(rules=rules_json([]), connect=False)
    fw.TICKER_ENABLED = True
    iface.connect()
    try:
        fw.status_due = True
        fw.status_sent_at = None
        deadline = __import__("time").monotonic() + 2
        while fw.status_due and __import__("time").monotonic() < deadline:
            __import__("time").sleep(0.01)
        assert not fw.status_due and fw.ticker.is_alive()
    finally:
        fw.ticker_stop.set()
        fw.ticker.join(1)
