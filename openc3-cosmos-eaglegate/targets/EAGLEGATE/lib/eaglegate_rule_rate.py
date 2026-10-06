"""Rate rule: deny packets that arrive faster than the spacecraft's beacon cadence.

  "type": "rate",
  "params": {
    "min_interval": 0.9   # seconds; set a little below the real cadence to allow jitter
  }

Tracked per APID. Only packets that arrive too EARLY can be filtered; a
beacon that never arrives is a monitoring problem, not a firewall decision.
"""
from dataclasses import dataclass, field

from eaglegate_rule import Rule
from eaglegate_validate import require, to_number

MAX_INTERVAL = 86400  # one day; anything longer is almost certainly a typo


@dataclass(kw_only=True)
class RateRule(Rule):
    TYPE = "rate"
    PARAM_KEYS = frozenset({"min_interval"})

    min_interval: float
    last_time: dict = field(default_factory=dict)  # APID -> arrival time of the last allowed packet

    @classmethod
    def parse_params(cls, params, where):
        require("min_interval" in params, f"{where} needs 'min_interval' (seconds)")
        interval = to_number(params["min_interval"], f"{where}.min_interval")
        require(0 < interval <= MAX_INTERVAL, f"{where}.min_interval must be in 0..{MAX_INTERVAL} seconds")
        return {"min_interval": interval}

    def fires(self, header, packet, now):
        last = self.last_time.get(header.apid)
        return last is not None and now - last < self.min_interval

    def record(self, header, now):
        self.last_time[header.apid] = now
