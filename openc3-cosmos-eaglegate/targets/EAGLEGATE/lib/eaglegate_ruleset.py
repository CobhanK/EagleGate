"""The active rule set: an ordered list of rules plus a default action."""
from dataclasses import dataclass

from eaglegate_ccsds_header import CcsdsHeader


@dataclass
class Ruleset:
    version: int          # from the rules file; -1 = the built-in deny-all set
    default_action: str   # used when no rule matches
    rules: list           # enabled Rule objects, in file order
    sha256: str           # hash of the exact file text, to confirm what is loaded
    default_hits: int = 0

    @classmethod
    def deny_all(cls):
        """Used until a valid rules file has been loaded (fail closed)."""
        return cls(version=-1, default_action="DENY", rules=[], sha256="")

    def evaluate(self, packet):
        """Return (action, rule_id) for one packet. FIRST matching rule wins.
        rule_id is None when no rule matched and the default action was used."""
        header = CcsdsHeader.from_bytes(packet)
        for rule in self.rules:
            if rule.matches(header, packet):
                rule.hits += 1
                return rule.action, rule.id
        self.default_hits += 1
        return self.default_action, None

    def summary(self):
        """Plain dict for interface_details()."""
        return {
            "version": self.version,
            "sha256": self.sha256,
            "default_action": self.default_action,
            "rule_count": len(self.rules),
            "rule_hits": {rule.id: rule.hits for rule in self.rules},
            "default_hits": self.default_hits,
        }
