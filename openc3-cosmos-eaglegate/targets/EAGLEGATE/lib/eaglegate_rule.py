"""The base class every rule type shares, plus the plain "match" rule.

A rule applies to a packet when its `match` conditions hold. It then FIRES
(and its action decides the packet) when its own check says so:

  match         fires on every packet it applies to         ALLOW or DENY
  range         a value is outside its documented limits    DENY only
  sequence      the sequence count is not the next one      DENY only
  rate          the packet came too soon after the last     DENY only
  authenticity  the MAC trailer is missing or wrong         DENY only

To add a rule type: subclass Rule in eaglegate_rule_types.py, set
TYPE and PARAM_KEYS, implement parse_params() and fires() (and record() if the
rule remembers earlier packets), then add it to RULE_TYPES in
eaglegate_rules_parser.py.
"""
from dataclasses import dataclass

from eaglegate_match import Match


@dataclass(kw_only=True)
class Rule:
    TYPE = None                # the "type" value in the rules file
    ACTIONS = ("DENY",)        # check rules can only deny
    PARAM_KEYS = frozenset()   # keys allowed in the rule's "params" object

    id: str
    action: str
    match: Match
    hits: int = 0              # how many packets this rule has decided

    @classmethod
    def parse_params(cls, params, where):
        """Validate the rule's "params" object; return constructor keyword arguments."""
        return {}

    def fires(self, header, packet, now):
        """True if this rule decides the packet. `now` is a monotonic time in seconds."""
        raise NotImplementedError

    def record(self, header, now):
        """Called once a packet this rule let through is finally ALLOWED.
        Stateful rules remember it here, never in fires(): otherwise a forged
        packet that a later rule denies could still change this rule's state."""


@dataclass(kw_only=True)
class MatchRule(Rule):
    """ALLOW or DENY every packet its match conditions select."""

    TYPE = "match"
    ACTIONS = ("ALLOW", "DENY")

    def fires(self, header, packet, now):
        return True
