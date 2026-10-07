"""The active rule set: an ordered list of rules plus a default action."""
import time
from dataclasses import dataclass

from eaglegate_ccsds_header import CcsdsHeader
from eaglegate_verdict import DEFAULT, RULE, Verdict


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
        """Return the Verdict for one packet. The FIRST rule that fires wins.
        `now` (monotonic seconds) is only passed in by tests."""
        header = CcsdsHeader.from_bytes(packet)
        now = time.monotonic() if now is None else now
        passed = []  # rules that applied to this packet but did not fire
        for rule in self.rules:
            if not rule.match.holds(header, packet):
                continue
            detail = rule.fires(header, packet, now)
            if detail is not None:
                rule.hits += 1
                return self._decide(passed, header, now, Verdict(
                    action=rule.action, stage=RULE, detail=detail, rule_id=rule.id,
                    rule_type=rule.TYPE, rule_description=rule.description,
                    rules_version=self.version, rules_sha256=self.sha256))
            passed.append(rule)
        self.default_hits += 1
        if self.version < 0:
            detail = "no valid rules file has been loaded; denying everything (see rules_error)"
        else:
            detail = f"no rule fired; default action {self.default_action}"
        return self._decide(passed, header, now, Verdict(
            action=self.default_action, stage=DEFAULT, detail=detail,
            rules_version=self.version, rules_sha256=self.sha256))

    @staticmethod
    def _decide(passed, header, now, verdict):
        """Stateful rules (sequence, rate) only remember packets that are ALLOWED."""
        if verdict.action == "ALLOW":
            for rule in passed:
                rule.record(header, now)
        return verdict

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
