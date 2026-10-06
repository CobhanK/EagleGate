"""Sequence rule: deny replayed, repeated or reordered packets.

  "type": "sequence",
  "params": {
    "max_gap": 1    # optional, default 1: only the very next count is accepted.
                    # N also accepts a jump of up to N, for links that lose packets.
  }

Counts are tracked per APID and wrap from 16383 to 0. The first packet of each
APID after the rules are (re)loaded sets the starting point, so reloading the
rules is also how operators recover after the spacecraft resets its counters.
"""
from dataclasses import dataclass, field

from eaglegate_ccsds_header import SEQ_COUNT_MODULO
from eaglegate_rule import Rule
from eaglegate_validate import to_int


@dataclass(kw_only=True)
class SequenceRule(Rule):
    TYPE = "sequence"
    PARAM_KEYS = frozenset({"max_gap"})

    max_gap: int = 1
    last_count: dict = field(default_factory=dict)  # APID -> count of the last allowed packet

    @classmethod
    def parse_params(cls, params, where):
        # Limited to half the count range, so "behind" and "ahead" stay distinguishable
        return {"max_gap": to_int(params.get("max_gap", 1), f"{where}.max_gap", 1, SEQ_COUNT_MODULO // 2)}

    def fires(self, header, packet, now):
        last = self.last_count.get(header.apid)
        if last is None:
            return False
        step = (header.seq_count - last) % SEQ_COUNT_MODULO  # how far ahead, allowing for wrap
        return not (1 <= step <= self.max_gap)

    def record(self, header, now):
        self.last_count[header.apid] = header.seq_count
