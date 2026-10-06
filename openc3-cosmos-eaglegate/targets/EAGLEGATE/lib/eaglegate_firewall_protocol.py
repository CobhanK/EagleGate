"""EAGLEGATE firewall: the entry point COSMOS loads from plugin.txt.

File name -> class name: COSMOS loads this file and expects a class named
`EaglegateFirewallProtocol`. Keep them in sync.

How a packet flows through the files in this folder:

  1. eaglegate_firewall_protocol.py  (this file)
       COSMOS calls read_data() with raw TCP bytes. LengthProtocol (the parent
       class) cuts them into single CCSDS packets.
  2. eaglegate_ccsds_header.py
       CcsdsHeader decodes the 6-byte header. The STRUCTURAL check (version 0,
       length <= max_length) runs here, before the rules, and cannot be turned
       off by the rules file.
  3. eaglegate_ruleset.py
       Ruleset.evaluate() checks each rule in order; the first rule that fires decides.
  4. eaglegate_match.py
       Match.holds() decides whether a rule applies to the packet at all.
  5. eaglegate_rule.py and eaglegate_rule_<type>.py
       Rule.fires() runs the rule's own check: match, range, sequence, rate or
       authenticity. Each type and its tunable "params" are in its own file.

How the rules get loaded (on connect, and on the RELOAD_RULES command):

  firewall_rules.json -> eaglegate_rules_parser.parse_rules() -> Ruleset
  (eaglegate_rules_error.RulesError if the file is invalid; the checks
  themselves live in eaglegate_validate.py)

  * reloading also resets what the sequence and rate rules remember

  * an invalid file never replaces a working rule set (last known good is kept);
    if no valid rules were ever loaded, everything is denied (fail closed)
  * the active version, sha256, per-rule hit counts and any load error are
    visible via interface_details("EAGLEGATE_INT")

Packets leaving this protocol are still UNIDENTIFIED; COSMOS identifies them
afterwards in the interface microservice.
"""
from datetime import datetime, timezone

from eaglegate_ccsds_header import CCSDS_HEADER_BYTES, CcsdsHeader
from eaglegate_rules_error import RulesError
from eaglegate_rules_parser import parse_rules
from eaglegate_ruleset import Ruleset
from openc3.environment import OPENC3_SCOPE
from openc3.interfaces.protocols.length_protocol import LengthProtocol
from openc3.utilities.logger import Logger

# Where the CCSDS length field is, in LengthProtocol's terms (same as "LENGTH 32 16 7"):
# starts at bit 32, is 16 bits long, and total packet bytes = field value + 7.
CCSDS_LENGTH_BIT_OFFSET = 32
CCSDS_LENGTH_BIT_SIZE = 16
CCSDS_LENGTH_VALUE_OFFSET = 7
CCSDS_LENGTH_BYTES_PER_COUNT = 1


class EaglegateFirewallProtocol(LengthProtocol):
    def __init__(
        self,
        max_length="1024",
        rules_file="EAGLEGATE/rules/firewall_rules.json",
        scope=None,
        allow_empty_data=None,
    ):
        super().__init__(
            CCSDS_LENGTH_BIT_OFFSET,
            CCSDS_LENGTH_BIT_SIZE,
            CCSDS_LENGTH_VALUE_OFFSET,
            CCSDS_LENGTH_BYTES_PER_COUNT,
            "BIG_ENDIAN",
            allow_empty_data=allow_empty_data,
        )
        self.fw_max_length = int(str(max_length), 0)  # plugin.txt passes strings
        self.rules_file = rules_file
        self.scope = scope if scope not in (None, "None", "") else OPENC3_SCOPE
        self.ruleset = Ruleset.deny_all()
        self.rules_loaded_at = None
        self.rules_error = None
        self.rules_error_at = None
        self.rejected = 0
        self.discarded_bytes = 0

    # ---- reading packets -----------------------------------------------------

    def read_data(self, data, extra=None):
        """Called by COSMOS with new bytes. Returns one allowed packet, or STOP.

        Why the loop: one TCP read can hold several packets. If we returned STOP
        for a denied packet, COSMOS would wait for MORE bytes from the socket
        before asking again, so an allowed packet already sitting in our buffer
        would be delayed. Instead we keep pulling packets from the buffer until
        one is allowed or the buffer is empty.
        """
        while True:
            data, extra = super().read_data(data, extra)  # next whole packet, or STOP
            if data in ("STOP", "DISCONNECT"):
                return (data, extra)
            ruleset = self.ruleset  # one reference per packet, in case of a reload
            try:
                action, rule_id = ruleset.evaluate(data)
            except Exception as error:  # an exception here would disconnect COSMOS
                action, rule_id = "DENY", f"error: {error}"
            if action == "ALLOW":
                return (data, extra)
            self._reject(
                f"APID 0x{CcsdsHeader.from_bytes(data).apid:03X} denied by "
                + (f"rule '{rule_id}'" if rule_id else "default action")
                + f" (rules v{ruleset.version})"
            )
            data = b""  # no new bytes; just take the next buffered packet

    def reduce_to_single_packet(self):
        """Called by LengthProtocol once it has bytes buffered.

        Why override it: we check the header as soon as its 6 bytes arrive,
        BEFORE LengthProtocol waits for the rest of the packet. A hostile header
        claiming 65 KB would otherwise make us buffer 65 KB first. If the header
        is bad, the framing can't be trusted, so the whole buffer is dropped.
        """
        if len(self.data) >= CCSDS_HEADER_BYTES:
            try:
                reason = self._structural_problem(CcsdsHeader.from_bytes(self.data))
            except Exception as error:  # fail closed
                reason = f"firewall error: {error}"
            if reason:
                dropped = len(self.data)
                self.data = b""
                self.discarded_bytes += dropped
                self._reject(f"{reason}; discarded {dropped} buffered bytes")
                return ("STOP", self.extra)
        return super().reduce_to_single_packet()

    def _structural_problem(self, header):
        """Hardcoded checks the rules file can never switch off. None = OK."""
        if header.version != 0:
            return f"bad CCSDS version {header.version}"
        if header.total_length > self.fw_max_length:
            return f"declared length {header.total_length} > {self.fw_max_length}"
        return None

    def _reject(self, reason):
        self.rejected += 1
        Logger.warn(f"{self._name()} firewall rejected: {reason} (total {self.rejected})")

    # ---- loading rules -------------------------------------------------------

    def connect_reset(self):
        """Called by COSMOS every time the interface (re)connects."""
        super().connect_reset()
        self.load_rules()

    def protocol_cmd(self, cmd_name, *cmd_args):
        """Called for interface_protocol_cmd("EAGLEGATE_INT", "RELOAD_RULES", ...)."""
        if str(cmd_name).upper() == "RELOAD_RULES":
            self.load_rules()
            return True
        return False

    def load_rules(self):
        """Parse the rules file and swap it in. Returns True on success.
        On failure the current rule set stays active and the error is recorded."""
        try:
            new_ruleset = parse_rules(self.read_rules_text())
        except Exception as error:
            self.rules_error = f"{type(error).__name__}: {error}"
            self.rules_error_at = _now()
            Logger.error(
                f"{self._name()} firewall: rules NOT loaded ({self.rules_error}); "
                f"keeping version {self.ruleset.version}"
                + (" (DENY ALL)" if self.ruleset.version < 0 else "")
            )
            return False
        old_version = self.ruleset.version
        # A single assignment: read_data sees the old or the new set, never a mix
        self.ruleset = new_ruleset
        self.rules_loaded_at = _now()
        self.rules_error = None
        self.rules_error_at = None
        Logger.info(
            f"{self._name()} firewall: rules version {old_version} -> {new_ruleset.version} "
            f"({len(new_ruleset.rules)} active rules, sha256 {new_ruleset.sha256[:12]})"
        )
        return True

    def read_rules_text(self):
        """Read the rules file: user-modified copy first, then the plugin original.
        Separate method so tests can replace it without a COSMOS bucket."""
        from openc3.utilities.target_file import TargetFile

        body = TargetFile.body(self.scope, self.rules_file)
        if body is None:
            raise RulesError(f"rules file {self.rules_file} not found")
        return body

    # ---- status --------------------------------------------------------------

    def read_details(self):
        """Adds a "firewall" section to interface_details()."""
        result = super().read_details()
        result["firewall"] = {
            "rules_file": self.rules_file,
            "rules": self.ruleset.summary(),
            "rules_loaded_at": self.rules_loaded_at,
            "rules_error": self.rules_error,
            "rules_error_at": self.rules_error_at,
            "rejected": self.rejected,
            "discarded_bytes": self.discarded_bytes,
            "max_length": self.fw_max_length,
        }
        return result

    def _name(self):
        return self.interface.name if self.interface else "?"


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
