"""The active rule set: an ordered list of rules plus a default action."""
import time
from dataclasses import dataclass

from eaglegate_ccsds_header import CcsdsHeader


@dataclass
class Ruleset:
    version: int          # from the rules file; -1 = the built-in deny-all set
    default_action: str   # used when no rule fires
    rules: list           # enabled Rule objects, in file order
    sha256: str           # hash of the exact file text, to confirm what is loaded
    default_hits: int = 0

    @classmethod
    def deny_all(cls):
        """Used until a valid rules file has been loaded (fail closed)."""
        return cls(version=-1, default_action="DENY", rules=[], sha256="")

    def evaluate(self, packet, now=None):
        """Return (action, rule_id) for one packet. The FIRST rule that fires wins.
        rule_id is None when no rule fired and the default action was used.
        `now` (monotonic seconds) is only passed in by tests."""
        header = CcsdsHeader.from_bytes(packet)
        now = time.monotonic() if now is None else now
        passed = []  # rules that applied to this packet but did not fire
        for rule in self.rules:
            if not rule.match.holds(header, packet):
                continue
            if rule.fires(header, packet, now):
                rule.hits += 1
                return self._decide(rule.action, rule.id, passed, header, now)
            passed.append(rule)
        self.default_hits += 1
        return self._decide(self.default_action, None, passed, header, now)

    @staticmethod
    def _decide(action, rule_id, passed, header, now):
        """Stateful rules (sequence, rate) only remember packets that are ALLOWED."""
        if action == "ALLOW":
            for rule in passed:
                rule.record(header, now)
        return action, rule_id

    def summary(self):
        """Plain dict for interface_details()."""
        return {
            "version": self.version,
            "sha256": self.sha256,
            "default_action": self.default_action,
            "rule_count": len(self.rules),
            "rule_types": {rule.id: rule.TYPE for rule in self.rules},
            "rule_hits": {rule.id: rule.hits for rule in self.rules},
            "default_hits": self.default_hits,
        }
