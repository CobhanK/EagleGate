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
  5. eaglegate_rule.py and eaglegate_rule_types.py
       Rule.fires() runs the rule's own check: match (in eaglegate_rule.py), or
       range, sequence, rate or authenticity (each a class in eaglegate_rule_types.py,
       with its tunable "params" in the class docstring).

If the FIRST packet of a connection is rejected (for any reason), the
connection is untrusted: every later byte is discarded until the interface
reconnects. A rejection after an allowed first packet affects only that packet.

Where rejected packets go (eaglegate_quarantine.py):

  * every rejection is a Verdict (eaglegate_verdict.py) saying which stage and
    rule decided and what the packet held, e.g. "INT16 at offset 12 = 120"
  * the packet and its Verdict are stored in a quarantine Valkey stream
  * the counts and the last reason are published as the FIREWALL_STATUS
    telemetry packet (at most once a second) for operator screens
  * the last few reasons are also in interface_details("EAGLEGATE_INT")

How the rules get loaded (on connect, and on the RELOAD_RULES command):

  firewall_rules.json -> eaglegate_rules_parser.parse_rules() -> Ruleset
  (eaglegate_rules_error.RulesError if the file is invalid; the checks
  themselves live in eaglegate_validate.py)

  * loading an UNCHANGED file (same sha256) keeps the running rule set, so
    reconnects never reset what the sequence and rate rules remember; a
    changed file starts them fresh

  * an invalid file never replaces a working rule set (last known good is kept);
    if no valid rules were ever loaded, everything is denied (fail closed)
  * the active version, sha256, per-rule hit counts and any load error are
    visible via interface_details("EAGLEGATE_INT")

Packets leaving this protocol are still UNIDENTIFIED; COSMOS identifies them
afterwards in the interface microservice.
"""
import time
from collections import deque

from eaglegate_ccsds_header import CCSDS_HEADER_BYTES, CcsdsHeader
from eaglegate_quarantine import RAW_CAPTURE_BYTES, QuarantineWriter, StatusPublisher, header_of, utc_now
from eaglegate_rules_error import RulesError
from eaglegate_rules_parser import parse_rules
from eaglegate_ruleset import Ruleset
from eaglegate_verdict import DEFAULT, ERROR, RULE, STRUCTURAL, UNTRUSTED, Verdict
from openc3.environment import OPENC3_SCOPE
from openc3.interfaces.protocols.length_protocol import LengthProtocol
from openc3.utilities.logger import Logger

# Where the CCSDS length field is, in LengthProtocol's terms (same as "LENGTH 32 16 7"):
# starts at bit 32, is 16 bits long, and total packet bytes = field value + 7.
CCSDS_LENGTH_BIT_OFFSET = 32
CCSDS_LENGTH_BIT_SIZE = 16
CCSDS_LENGTH_VALUE_OFFSET = 7
CCSDS_LENGTH_BYTES_PER_COUNT = 1

RECENT_REJECTIONS = 20   # reasons kept for interface_details()
STATUS_INTERVAL = 1.0    # seconds between FIREWALL_STATUS packets while rejecting


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
        self.target_name = rules_file.split("/")[0]  # "EAGLEGATE/rules/..." -> EAGLEGATE
        self.scope = scope if scope not in (None, "None", "") else OPENC3_SCOPE
        self.ruleset = Ruleset.deny_all()
        self.rules_loaded_at = None
        self.rules_error = None
        self.rules_error_at = None
        self.rejected = 0
        self.rejected_by_stage = {RULE: 0, DEFAULT: 0, ERROR: 0, STRUCTURAL: 0}
        self.discarded_bytes = 0
        self.first_packet_decided = False  # has this connection's first packet been judged?
        self.connection_untrusted = False  # first packet was rejected: deny all until reconnect
        self.connection_id = 0             # counts connections, to group quarantine entries
        self.untrusted_captured = 0        # bytes of this untrusted connection kept as evidence
        self.recent = deque(maxlen=RECENT_REJECTIONS)
        self.last_rejection = None
        # Created on first connect, once the interface name is known
        self.quarantine = None
        self.status = None
        self.status_due = False            # counts changed since the last status packet
        self.status_sent_at = None

    # ---- reading packets -----------------------------------------------------

    def read_data(self, data, extra=None):
        """Called by COSMOS with new bytes. Returns one allowed packet, or STOP.

        Why the loop: one TCP read can hold several packets. If we returned STOP
        for a denied packet, COSMOS would wait for MORE bytes from the socket
        before asking again, so an allowed packet already sitting in our buffer
        would be delayed. Instead we keep pulling packets from the buffer until
        one is allowed or the buffer is empty.

        If the first packet of a connection is rejected, the whole connection is
        untrusted: every later byte is discarded until the interface reconnects.
        """
        self._publish_status_if_due()  # catches up after a burst of rejections ends
        while True:
            if self.connection_untrusted:
                return self._discard_all(data, extra)
            data, extra = super().read_data(data, extra)  # next whole packet, or STOP
            if data in ("STOP", "DISCONNECT"):
                return (data, extra)
            ruleset = self.ruleset  # one reference per packet, in case of a reload
            try:
                verdict = ruleset.evaluate(data)
            except Exception as error:  # an exception here would disconnect COSMOS
                verdict = Verdict(action="DENY", stage=ERROR, detail=f"rules engine error: {error}",
                                  rules_version=ruleset.version, rules_sha256=ruleset.sha256)
            if verdict.action == "ALLOW":
                self.first_packet_decided = True
                return (data, extra)
            self._reject(verdict, data)
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
                dropped = self.data
                self.data = b""
                self.discarded_bytes += len(dropped)
                ruleset = self.ruleset
                self._reject(Verdict(action="DENY", stage=STRUCTURAL,
                                     detail=f"{reason}; discarded {len(dropped)} buffered bytes",
                                     rules_version=ruleset.version, rules_sha256=ruleset.sha256),
                             dropped)
                return ("STOP", self.extra)
        return super().reduce_to_single_packet()

    def _structural_problem(self, header):
        """Hardcoded checks the rules file can never switch off. None = OK."""
        if header.version != 0:
            return f"bad CCSDS version {header.version}"
        if header.total_length > self.fw_max_length:
            return f"declared length {header.total_length} > {self.fw_max_length}"
        return None

    def _reject(self, verdict, data):
        """Count, log and quarantine one rejected packet (or unframed buffer)."""
        self.rejected += 1
        self.rejected_by_stage[verdict.stage] += 1
        Logger.warn(f"{self._name()} firewall rejected {_apid(data)}: {verdict.reason()} "
                    f"(total {self.rejected})")
        self._quarantine(verdict, data)
        if not self.first_packet_decided:
            self.first_packet_decided = True
            self.connection_untrusted = True
            Logger.error(
                f"{self._name()} firewall: first packet of the connection was rejected; "
                "discarding everything until the interface reconnects"
            )
            # Once per connection, so not throttled: the link may now go quiet,
            # and screens must not keep showing a trusted connection
            self._publish_status_if_due(force=True)
            return
        self._publish_status_if_due()

    def _discard_all(self, data, extra):
        """Drop new and buffered bytes without framing them (logged once, in _reject).
        The first RAW_CAPTURE_BYTES of the connection are kept as evidence."""
        dropped = self.data + data
        self.discarded_bytes += len(dropped)
        self.data = b""
        if dropped and self.untrusted_captured < RAW_CAPTURE_BYTES:
            kept = dropped[:RAW_CAPTURE_BYTES - self.untrusted_captured]
            self.untrusted_captured += len(kept)
            ruleset = self.ruleset
            self._quarantine(Verdict(
                action="DENY", stage=UNTRUSTED,
                detail=f"connection untrusted since its first packet was rejected; "
                       f"discarded {len(dropped)} bytes" + (f", kept {len(kept)}" if len(kept) < len(dropped) else ""),
                rules_version=ruleset.version, rules_sha256=ruleset.sha256), kept)
        if dropped:
            self.status_due = True  # DISCARDED_BYTES changed
        self._publish_status_if_due()
        return ("STOP", extra)

    def _quarantine(self, verdict, data):
        """Store the rejected bytes with their Verdict; remember the reason for operators."""
        time_text = utc_now()
        entry_id = self._quarantine_writer().record(verdict, data, self.connection_id, time_text)
        header = header_of(verdict, data)
        rejection = {
            "time": time_text,
            "stage": verdict.stage,
            "rule_id": verdict.rule_id,
            "apid": f"0x{header.apid:03X}" if header else None,
            "seq_count": header.seq_count if header else None,
            "reason": verdict.reason(),
            "entry_id": entry_id,  # None if it could not be stored
        }
        self.recent.append(rejection)
        if verdict.stage != UNTRUSTED:
            # Discarded bytes are a consequence: keep showing the rejection that caused it
            self.last_rejection = rejection
        self.status_due = True

    def _quarantine_writer(self):
        if self.quarantine is None:
            self.quarantine = QuarantineWriter(self.scope, self._name())
        return self.quarantine

    # ---- status packet -------------------------------------------------------

    def _publish_status_if_due(self, force=False):
        """Publish FIREWALL_STATUS when something changed, at most once per
        STATUS_INTERVAL, so a flood of rejections cannot flood telemetry too."""
        now = time.monotonic()
        if not force:
            if not self.status_due:
                return
            if self.status_sent_at is not None and now - self.status_sent_at < STATUS_INTERVAL:
                return
        if self.status is None:
            self.status = StatusPublisher(self.scope, self.target_name)
        self.status_sent_at = now
        # A failed publish stays due, so the screen catches up once publishing works again
        self.status_due = not self.status.publish(self.status_items())

    def status_items(self):
        """FIREWALL_STATUS item values (see cmd_tlm/tlm.txt)."""
        last = self.last_rejection or {}
        writer = self.quarantine
        return {
            # Counters are 32-bit items; a long flood can pass 2**32 and an out-of-range
            # value would make every publish fail, so they stop at the maximum instead
            "REJECTED": _u32(self.rejected),
            "DENIED_RULE": _u32(self.rejected_by_stage[RULE]),
            "DENIED_DEFAULT": _u32(self.rejected_by_stage[DEFAULT]),
            "DENIED_ERROR": _u32(self.rejected_by_stage[ERROR]),
            "DENIED_STRUCTURAL": _u32(self.rejected_by_stage[STRUCTURAL]),
            "DISCARDED_BYTES": _u32(self.discarded_bytes),
            "QUARANTINED": _u32(writer.written if writer else 0),
            "QUARANTINE_ERRORS": _u32((writer.errors + writer.skipped) if writer else 0),
            "CONNECTION_UNTRUSTED": "TRUE" if self.connection_untrusted else "FALSE",
            "RULES_VERSION": self.ruleset.version,
            "LAST_TIME": last.get("time") or "",
            "LAST_STAGE": last.get("stage") or "",
            "LAST_RULE_ID": last.get("rule_id") or "",
            "LAST_APID": last.get("apid") or "",
            "LAST_REASON": last.get("reason") or "",
            "LAST_ENTRY_ID": last.get("entry_id") or "",
        }

    # ---- loading rules -------------------------------------------------------

    def connect_reset(self):
        """Called by COSMOS every time the interface TRIES to (re)connect: it runs
        before the socket is opened, so also every few seconds while the link is down."""
        super().connect_reset()
        was_untrusted = self.connection_untrusted
        old_ruleset = self.ruleset
        self.first_packet_decided = False  # a new connection gets a fresh start
        self.connection_untrusted = False
        self.untrusted_captured = 0
        self.connection_id += 1  # counts attempts; only connected ones get quarantine entries
        self.load_rules()
        # Publish only what screens would see change, not once per retry of a dead link
        if self.status_sent_at is None or was_untrusted or self.ruleset is not old_ruleset:
            self._publish_status_if_due(force=True)

    def protocol_cmd(self, cmd_name, *cmd_args):
        """Called for interface_protocol_cmd("EAGLEGATE_INT", "RELOAD_RULES", ...)."""
        if str(cmd_name).upper() == "RELOAD_RULES":
            self.load_rules()
            # Runs on the interface's command thread: leave publishing the new
            # RULES_VERSION to the read thread, so only one thread writes the packet
            self.status_due = True
            return True
        return False

    def load_rules(self):
        """Parse the rules file and swap it in. Returns True on success.
        On failure the current rule set stays active and the error is recorded."""
        try:
            new_ruleset = parse_rules(self.read_rules_text())
        except Exception as error:
            self.rules_error = f"{type(error).__name__}: {error}"
            self.rules_error_at = utc_now()
            Logger.error(
                f"{self._name()} firewall: rules NOT loaded ({self.rules_error}); "
                f"keeping version {self.ruleset.version}"
                + (" (DENY ALL)" if self.ruleset.version < 0 else "")
            )
            return False
        self.rules_error = None
        self.rules_error_at = None
        if new_ruleset.sha256 == self.ruleset.sha256:
            # Same file: keep the running set, so what the sequence and rate rules
            # remember survives reconnects (a reset would let one replay through)
            return True
        old_version = self.ruleset.version
        # A single assignment: read_data sees the old or the new set, never a mix
        self.ruleset = new_ruleset
        self.rules_loaded_at = utc_now()
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
            "rejected_by_stage": dict(self.rejected_by_stage),
            "discarded_bytes": self.discarded_bytes,
            "connection_untrusted": self.connection_untrusted,
            "connection_id": self.connection_id,
            "max_length": self.fw_max_length,
            "quarantine": {
                **(self.quarantine.summary() if self.quarantine else {}),
                "recent": list(reversed(self.recent)),  # newest first; reasons only, no bytes
            },
            "status_packet": {
                "published": self.status.published if self.status else 0,
                "errors": self.status.errors if self.status else 0,
                "last_error": self.status.last_error if self.status else None,
            },
        }
        return result

    def _name(self):
        return self.interface.name if self.interface else "?"


def _u32(count):
    return min(count, 0xFFFFFFFF)


def _apid(data):
    """"APID 0x002" for log lines; raw buffers may be too short for a header."""
    if len(data) < CCSDS_HEADER_BYTES:
        return f"{len(data)} bytes"
    return f"APID 0x{CcsdsHeader.from_bytes(data).apid:03X}"
