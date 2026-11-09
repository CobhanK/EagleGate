"""The firewall's decision about one packet, with the reason an operator sees."""
from dataclasses import dataclass

# Where the decision was made
RULE = "RULE"              # a rule in the rules file fired
DEFAULT = "DEFAULT"        # no rule fired; the file's default_action decided
ERROR = "ERROR"            # evaluating the rules raised an exception (fail closed)
STRUCTURAL = "STRUCTURAL"  # the hardcoded header check failed; the bytes were never framed
UNTRUSTED = "UNTRUSTED"    # the connection's first packet was rejected; bytes discarded unframed
LINK = "LINK"              # an extension in front of the firewall (eaglegate_extensions.py)
                           # rejected bytes below the packet layer, e.g. a transfer frame
STAGES = (RULE, DEFAULT, ERROR, STRUCTURAL, UNTRUSTED, LINK)

# Stages that judged one whole, framed packet. Only these could ever be released
# back into COSMOS; STRUCTURAL, UNTRUSTED and LINK bytes are kept for forensics only.
FRAMED_STAGES = frozenset({RULE, DEFAULT, ERROR})


@dataclass(frozen=True)
class Verdict:
    action: str                  # ALLOW or DENY
    stage: str                   # one of STAGES
    detail: str = ""             # what was checked and what the packet actually held
    rule_id: str = None          # the rule that decided (RULE stage only)
    rule_type: str = None
    rule_description: str = ""   # the rule's "description" from the rules file
    rules_version: int = None    # the rule set that was active
    rules_sha256: str = ""
    layer: str = ""              # LINK stage: which layer of the extension decided, e.g. "frame"

    @property
    def framed(self):
        return self.stage in FRAMED_STAGES

    def reason(self):
        """One line for logs and operator displays."""
        if self.stage == RULE:
            who = f"rule '{self.rule_id}'"
        elif self.stage == DEFAULT:
            who = "default action"
        elif self.stage == LINK:
            who = f"link layer '{self.layer}'" if self.layer else "link layer"
        else:
            who = self.stage.lower()
        return f"{self.action} by {who}: {self.detail} (rules v{self.rules_version})"
