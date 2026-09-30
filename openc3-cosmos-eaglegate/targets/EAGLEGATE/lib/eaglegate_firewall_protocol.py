"""EAGLEGATE firewall: CCSDS Space Packet framing + user-editable rules.

File name -> class name: COSMOS loads this file and expects a class named
`EaglegateFirewallProtocol`. Keep them in sync.

Two layers:

* STRUCTURAL floor (hardcoded, NOT user-editable): bad CCSDS version or declared
  length above the plugin's fw_max_length. Framing can't be trusted, so the
  receive buffer is discarded before the body is buffered. A bad rules file can
  never switch this off.

* RULES (user-editable, targets/EAGLEGATE/rules/firewall_rules.json): evaluated
  on each correctly framed packet, first match wins. A DENY skips exactly that
  packet and the next buffered packet is delivered immediately.

Rules lifecycle:
  * loaded when the interface connects
  * reloaded on demand:  interface_protocol_cmd("EAGLEGATE_INT", "RELOAD_RULES", read_write="READ")
  * an invalid file never replaces a working rule set (last known good is kept);
    if no valid rules were ever loaded, everything is denied (fail closed)
  * the active version, sha256, per-rule hit counts and any load error are
    visible via interface_details("EAGLEGATE_INT")

Packets leaving this protocol are still UNIDENTIFIED; COSMOS identifies them
afterwards in the interface microservice.
"""
from datetime import datetime, timezone

from eaglegate_rules import RulesError, compile_ruleset, deny_all, parse_header
from openc3.environment import OPENC3_SCOPE
from openc3.interfaces.protocols.length_protocol import LengthProtocol
from openc3.utilities.logger import Logger

CCSDS_HEADER_BYTES = 6


class EaglegateFirewallProtocol(LengthProtocol):
    def __init__(
        self,
        length_bit_offset="32",
        length_bit_size="16",
        length_value_offset="7",
        length_bytes_per_count="1",
        length_endianness="BIG_ENDIAN",
        max_length="1024",
        rules_file="EAGLEGATE/rules/firewall_rules.json",
        scope=None,
        allow_empty_data=None,
    ):
        super().__init__(
            length_bit_offset,
            length_bit_size,
            length_value_offset,
            length_bytes_per_count,
            length_endianness,
            allow_empty_data=allow_empty_data,
        )
        self.fw_max_length = int(str(max_length), 0)
        self.rules_file = rules_file
        self.scope = scope if scope not in (None, "None", "") else OPENC3_SCOPE
        self.ruleset = deny_all("no rules loaded yet")
        self.rules_loaded_at = None
        self.rules_error = None
        self.rules_error_at = None
        self.rejected = 0
        self.discarded_bytes = 0

    # ---- rules loading -------------------------------------------------------

    def read_rules_text(self):
        """Read the rules file: user-modified copy first, then the plugin original.
        Separate method so tests can replace it without a COSMOS bucket."""
        from openc3.utilities.target_file import TargetFile

        body = TargetFile.body(self.scope, self.rules_file)
        if body is None:
            raise RulesError(f"rules file {self.rules_file} not found")
        return body

    def load_rules(self):
        """Compile and hot-swap the rules. Returns True on success.
        On failure the current rule set stays active and the error is recorded."""
        name = self.interface.name if self.interface else "?"
        try:
            new_rules = compile_ruleset(self.read_rules_text())
        except Exception as error:
            self.rules_error = f"{type(error).__name__}: {error}"
            self.rules_error_at = _now()
            Logger.error(
                f"{name} firewall: rules NOT loaded ({self.rules_error}); "
                f"keeping version {self.ruleset.version}"
                + (" (DENY ALL)" if self.ruleset.version < 0 else "")
            )
            return False
        old_version = self.ruleset.version
        # Single reference assignment: the read thread sees old or new, never a mix
        self.ruleset = new_rules
        self.rules_loaded_at = _now()
        self.rules_error = None
        self.rules_error_at = None
        Logger.info(
            f"{name} firewall: rules version {old_version} -> {new_rules.version} "
            f"({len(new_rules.rules)} active rules, sha256 {new_rules.sha256[:12]})"
        )
        return True

    def connect_reset(self):
        super().connect_reset()
        self.load_rules()

    def protocol_cmd(self, cmd_name, *cmd_args):
        if str(cmd_name).upper() == "RELOAD_RULES":
            self.load_rules()
            return True
        return False

    def read_details(self):
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

    # ---- structural floor ----------------------------------------------------

    def structural_reason(self, header_bytes):
        header = parse_header(header_bytes)
        if header.version != 0:
            return f"bad CCSDS version {header.version}"
        if header.total_length > self.fw_max_length:
            return f"declared length {header.total_length} > {self.fw_max_length}"
        return None

    def reduce_to_single_packet(self):
        if len(self.data) >= CCSDS_HEADER_BYTES:
            try:
                reason = self.structural_reason(self.data)
            except Exception as error:  # fail closed
                reason = f"firewall error: {error}"
            if reason:
                dropped = len(self.data)
                self.data = b""
                self.discarded_bytes += dropped
                self._reject(f"{reason}; discarded {dropped} buffered bytes")
                return ("STOP", self.extra)
        return super().reduce_to_single_packet()

    # ---- rules evaluation ----------------------------------------------------

    def read_data(self, data, extra=None):
        while True:
            data, extra = super().read_data(data, extra)
            if data in ("STOP", "DISCONNECT"):
                return (data, extra)
            ruleset = self.ruleset  # take one reference per packet
            try:
                action, rule_id = ruleset.evaluate(data)
            except Exception as error:  # fail closed
                action, rule_id = "DENY", f"error: {error}"
            if action == "ALLOW":
                return (data, extra)
            header = parse_header(data)
            self._reject(
                f"APID 0x{header.apid:03X} denied by "
                + (f"rule '{rule_id}'" if rule_id else "default action")
                + f" (rules v{ruleset.version})"
            )
            data = b""  # immediately drain the next buffered packet, if any

    def _reject(self, reason):
        self.rejected += 1
        name = self.interface.name if self.interface else "?"
        Logger.warn(f"{name} firewall rejected: {reason} (total {self.rejected})")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
