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
reconnects, or an admin restores trust (RESTORE_TRUST below). A rejection after
an allowed first packet affects only that packet. The rules file's
settings.untrust_on_first_packet_reject turns this off.

Where rejected packets go (eaglegate_quarantine.py):

  * every rejection is a Verdict (eaglegate_verdict.py) saying which stage and
    rule decided and what the packet held, e.g. "INT16 at offset 12 = 120"
  * the packet and its Verdict are stored in a quarantine Valkey stream
  * the counts and the last reason are published as the FIREWALL_STATUS
    telemetry packet (at most once a second) for operator screens
  * the last few reasons are also in interface_details("EAGLEGATE_INT")

Every packet judged, allowed or not, is also counted per APID
(eaglegate_traffic.py): totals, bytes and sequence gaps, shown in
FIREWALL_STATUS and the page's Link status tab.

Spike warning (eaglegate_spike.py): rejections are also counted per window and
compared with what is normal for the link. FIREWALL_STATUS SPIKE_STATE turns
YELLOW or RED, which COSMOS's limits system turns into a notification or an
alert. A ticker thread closes windows and publishes even when no bytes arrive.

The last 10 rejections (no bytes, cleaned text) are published as the
FIREWALL_RECENT packet for the FIREWALLREJECTIONS Telemetry Viewer widget.

How the rules get loaded (eaglegate_rules_store.py has the storage keys and
why they are admin-only):

  on connect:    rules_active.json, or the plugin's rules/firewall_rules.json
                 until a rule set has been applied
  RELOAD_RULES:  rules_pending.json (uploaded by an admin); if it is valid it
                 becomes the running set and is saved as rules_active.json

  text -> eaglegate_rules_parser.parse_rules() -> Ruleset
  (eaglegate_rules_error.RulesError if the file is invalid; the checks
  themselves live in eaglegate_validate.py)

  * loading UNCHANGED text (same sha256) keeps the running rule set, so
    reconnects never reset what the sequence and rate rules remember; a
    changed file starts them fresh
  * an invalid file never replaces a working rule set (last known good is kept);
    if no valid rules were ever loaded, everything is denied (fail closed)
  * with a signing key configured (eaglegate_rules_signing.py) the firewall
    signs every set it activates and only loads a correctly signed
    rules_active.json: a file changed directly in the bucket is refused
  * RELOAD_RULES may name the sha256 the editor started from and the sha256 of
    the file it uploaded; a mismatch (someone else applied or uploaded in the
    meantime) is refused, so one admin cannot silently overwrite another
  * the active version, sha256, source, per-rule hit counts and any load error
    are visible via interface_details("EAGLEGATE_INT")

RESTORE_TRUST <sha256>: an admin uploads requests/restore_trust.json from the
EagleGate Firewall page, then sends this command with its sha256
(eaglegate_admin_requests.py: an operator's command alone cannot do it). The
connection keeps its socket, which matters when the sender never reconnects.

RELEASE <sha256>: the same, with requests/release.json naming one quarantine
entry: the firewall sends that packet on into COSMOS without checking the
rules again, at most once per entry (eaglegate_release.py).

Extensions (eaglegate_extensions.py): protocols placed BEFORE this one on the
interface may own a section of the rules file and attach link information to
packets. They use the "Extension API" methods below.

Packets leaving this protocol are still UNIDENTIFIED; COSMOS identifies them
afterwards in the interface microservice.
"""
import threading
import time
from collections import deque

from eaglegate_admin_requests import NonceLog, RequestError, parse_request
from eaglegate_ccsds_header import CCSDS_HEADER_BYTES, CcsdsHeader
from eaglegate_extensions import FIREWALL_API_VERSION, collect_extensions, link_of
from eaglegate_release import ReleaseError, check_entry, deliver, release_params
from eaglegate_quarantine import (RAW_CAPTURE_BYTES, RECENT_COUNT, RECENT_PACKET, QuarantineWriter, StatusPublisher,
                                  header_of, recent_items, utc_now)
from eaglegate_rules_error import RulesError
from eaglegate_rules_parser import TOP_LEVEL_KEYS, parse_rules
from eaglegate_rules_signing import RulesSigner
from eaglegate_rules_store import RulesStore
from eaglegate_ruleset import Ruleset
from eaglegate_spike import SPIKE, STATE_NAMES, SpikeDetector
from eaglegate_traffic import TrafficCounter
from eaglegate_verdict import DEFAULT, ERROR, LINK, RULE, STRUCTURAL, UNTRUSTED, Verdict
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
RECENT_ADMIN_ACTIONS = 20
STATUS_INTERVAL = 1.0    # seconds between FIREWALL_STATUS packets while rejecting
TICK_SECONDS = 1.0       # how often the ticker thread closes spike windows and publishes
NOTIFICATION = "notification"  # COSMOS Logger type: shown in every tool's notification menu


class EaglegateFirewallProtocol(LengthProtocol):
    # Extensions look for this attribute to find the firewall on their interface
    EAGLEGATE_FIREWALL_API = FIREWALL_API_VERSION
    TICKER_ENABLED = True  # tests switch the ticker thread off and call tick_spike() themselves
    clock = staticmethod(time.monotonic)  # spike windows; tests replace it

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
        self.rules_source = None           # "active", "original" or "pending": where the running set came from
        self.persist_error = None          # set when an applied set could not be saved as rules_active.json
        self.rules_store = None            # created on first use, once the scope is final
        self.signer = RulesSigner()        # reads EAGLEGATE_RULES_KEY; disabled when unset
        self.rules_signed = False          # the running set was verified, or signed when applied
        self.rejected = 0
        self.rejected_by_stage = {RULE: 0, DEFAULT: 0, ERROR: 0, STRUCTURAL: 0, LINK: 0}
        self.discarded_bytes = 0
        self.traffic = TrafficCounter()    # every judged packet, allowed or not
        self.first_packet_decided = False  # has this connection's first packet been judged?
        self.connection_untrusted = False  # first packet was rejected: deny all until reconnect
        self.untrusted_since = None
        self.untrusted_cause = None        # the rejection that made it untrusted, for the page
        self.trust_restores = 0
        self.released = 0                  # quarantined packets an admin sent on (RELEASE)
        self.extensions = {}               # section -> Extension, found when the rules load
        self.nonces = NonceLog()           # admin requests already used
        self.admin_actions = deque(maxlen=RECENT_ADMIN_ACTIONS)
        self.interface_warning = None      # set when the interface type cannot work (see connect_reset)
        self.connection_id = 0             # counts connections, to group quarantine entries
        self.untrusted_captured = 0        # bytes of this untrusted connection kept as evidence
        self.recent = deque(maxlen=RECENT_REJECTIONS)
        self.last_rejection = None
        # Created on first connect, once the interface name is known
        self.quarantine = None
        self.status = None
        self.status_due = False            # counts changed since the last status packet
        self.status_sent_at = None
        self.recent_due = True             # FIREWALL_RECENT changed (published once on first connect)
        self.spike = SpikeDetector()       # rejection spike warning (eaglegate_spike.py)
        self.publish_lock = threading.RLock()  # the read and ticker threads both publish
        self.ticker = None
        self.ticker_stop = threading.Event()

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
            link = link_of(extra)    # set by an extension in front of the firewall, else None
            try:
                verdict = ruleset.evaluate(data, link=link)
            except Exception as error:  # an exception here would disconnect COSMOS
                verdict = Verdict(action="DENY", stage=ERROR, detail=f"rules engine error: {error}",
                                  rules_version=ruleset.version, rules_sha256=ruleset.sha256)
            self.traffic.record(data, verdict.action == "ALLOW")
            self.spike.packet()
            if verdict.action == "ALLOW":
                self.first_packet_decided = True
                self.status_due = True  # PACKETS and ALLOWED changed; published at most once a second
                return (data, extra)
            self._reject(verdict, data, link)
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

    def _reject(self, verdict, data, link=None):
        """Count, log and quarantine one rejected packet (or unframed buffer)."""
        self._record_rejection(verdict, data, link)
        if not self.first_packet_decided:
            self.first_packet_decided = True
            if self.ruleset.settings.get("untrust_on_first_packet_reject", True):
                self.mark_untrusted("its first packet was rejected", verdict)
                return
        self._publish_status_if_due()

    def _record_rejection(self, verdict, data, link=None):
        self.rejected += 1
        self.rejected_by_stage[verdict.stage] = self.rejected_by_stage.get(verdict.stage, 0) + 1
        self.spike.rejection(verdict)
        what = f"{len(data)} link-layer bytes" if verdict.stage == LINK else _apid(data)
        Logger.warn(f"{self._name()} firewall rejected {what}: {verdict.reason()} (total {self.rejected})")
        self._quarantine(verdict, data, link)

    def _discard_all(self, data, extra):
        """Drop new and buffered bytes without framing them (logged once, in _reject).
        The first RAW_CAPTURE_BYTES of the connection are kept as evidence."""
        dropped = self.data + data
        self.data = b""
        self.discard_untrusted(dropped)
        return ("STOP", extra)

    def _quarantine(self, verdict, data, link=None):
        """Store the rejected bytes with their Verdict; remember the reason for operators."""
        time_text = utc_now()
        entry_id = self._quarantine_writer().record(verdict, data, self.connection_id, time_text, link)
        header = header_of(verdict, data)
        rejection = {
            "time": time_text,
            "interface": self._name(),
            "stage": verdict.stage,
            "rule_id": verdict.rule_id,
            "rule_type": verdict.rule_type,
            "apid": f"0x{header.apid:03X}" if header else None,
            "seq_count": header.seq_count if header else None,
            "packet_type": ("CMD" if header.packet_type else "TLM") if header else None,
            "length": len(data),
            "layer": verdict.layer or None,
            "link": link,
            "reason": verdict.reason(),
            "entry_id": entry_id,  # None if it could not be stored
        }
        if verdict.framed:
            # Kept only until FIREWALL_RECENT names the packet (_name_recent); never shown
            rejection["_data"] = bytes(data)
        self.recent.append(rejection)
        if verdict.stage != UNTRUSTED:
            # Discarded bytes are a consequence: keep showing the rejection that caused it
            self.last_rejection = rejection
        self.status_due = True
        self.recent_due = True

    def _quarantine_writer(self):
        if self.quarantine is None:
            self.quarantine = QuarantineWriter(self.scope, self._name())
        return self.quarantine

    # ---- Extension API -------------------------------------------------------
    # Stable methods for protocols in front of the firewall (eaglegate_extensions.py,
    # FIREWALL_API_VERSION). They run on the interface's read thread, except
    # admin_request() and record_admin_action(), which run on its command thread.

    def reject(self, verdict, data, link=None):
        """Count, log and quarantine a rejection the extension made (usually stage
        LINK, with verdict.layer set). It does not affect trust: the extension
        decides that and calls mark_untrusted() itself."""
        self._record_rejection(verdict, data, link)
        self._publish_status_if_due()

    def mark_untrusted(self, cause, verdict=None):
        """Discard everything on this connection until it reconnects or an admin
        restores trust. Returns False if it already was untrusted."""
        if self.connection_untrusted:
            return False
        self.connection_untrusted = True
        self.untrusted_since = utc_now()
        self.untrusted_cause = f"{cause}: {verdict.reason()}" if verdict else cause
        Logger.error(f"{self._name()} firewall: connection untrusted ({self.untrusted_cause}); discarding "
                     "everything until the interface reconnects or an admin restores trust")
        # Not throttled: the link may now go quiet, and screens must not keep
        # showing a trusted connection
        self._publish_status_if_due(force=True)
        return True

    def discard_untrusted(self, dropped):
        """Count bytes dropped because the connection is untrusted, keeping the
        first RAW_CAPTURE_BYTES of the connection as evidence."""
        self.discarded_bytes += len(dropped)
        if dropped and self.untrusted_captured < RAW_CAPTURE_BYTES:
            kept = dropped[:RAW_CAPTURE_BYTES - self.untrusted_captured]
            self.untrusted_captured += len(kept)
            ruleset = self.ruleset
            self._quarantine(Verdict(
                action="DENY", stage=UNTRUSTED,
                detail=f"connection untrusted ({self.untrusted_cause or 'first packet rejected'}); "
                       f"discarded {len(dropped)} bytes" + (f", kept {len(kept)}" if len(kept) < len(dropped) else ""),
                rules_version=ruleset.version, rules_sha256=ruleset.sha256), kept)
        if dropped:
            self.status_due = True  # DISCARDED_BYTES changed
        self._publish_status_if_due()

    def admin_request(self, kind, request_sha256):
        """Read, check and consume requests/{kind}.json (eaglegate_admin_requests.py).
        Returns the AdminRequest; raises RequestError saying why it was refused."""
        try:
            text = self.store().read_request(kind)
        except Exception as error:
            raise RequestError(f"could not read the {kind} request: {type(error).__name__}: {error}") from None
        request = parse_request(text, kind, request_sha256)
        self.nonces.use(request.nonce)
        if not self.store().delete_request(kind):
            # Not fatal: the nonce is remembered, so the file cannot act twice
            Logger.warn(f"{self._name()} firewall: could not delete the used {kind} request: "
                        f"{self.store().last_error}")
        return request

    def record_admin_action(self, action, ok, detail, request=None, **fields):
        """Remember an admin action for interface_details (the page polls it) and
        write it to the audit stream. Returns ok."""
        entry = {"time": utc_now(), "action": action, "ok": ok, "detail": detail,
                 **(request.audit_fields() if request else {}), **fields}
        entry["audit_id"] = self._quarantine_writer().audit(entry)
        self.admin_actions.append(entry)
        log = Logger.warn if ok else Logger.error
        log(f"{self._name()} firewall: {action} {'done' if ok else 'refused'}: {detail}"
            + (f" (reason: {request.reason}; requested by {request.requested_by or '?'})" if request else ""))
        return ok

    def restore_trust(self, request_sha256):
        """RESTORE_TRUST: the admin side of an untrusted connection. Keeps the socket
        (the sender may never reconnect on its own). Returns True when done."""
        try:
            request = self.admin_request("restore_trust", request_sha256)
        except RequestError as error:
            return self.record_admin_action("RESTORE_TRUST", False, str(error),
                                            request_sha256=request_sha256 or "")
        if not self.connection_untrusted:
            return self.record_admin_action("RESTORE_TRUST", True, "the connection was not untrusted; "
                                            "nothing changed", request)
        cause, since = self.untrusted_cause, self.untrusted_since
        self.connection_untrusted = False
        self.untrusted_cause = None
        self.untrusted_since = None
        self.first_packet_decided = True  # from now on a rejection affects only its own packet
        self.trust_restores += 1
        return self.record_admin_action("RESTORE_TRUST", True, f"trust restored (untrusted since {since}: {cause})",
                                        request, previous_cause=cause)

    def release(self, request_sha256):
        """RELEASE: send one quarantined packet on into COSMOS (eaglegate_release.py).
        Runs on the command thread. Returns True when the packet was delivered."""
        try:
            request = self.admin_request("release", request_sha256)
        except RequestError as error:
            return self.record_admin_action("RELEASE", False, str(error), request_sha256=request_sha256 or "")
        entry_id = ""
        try:
            entry_id, digest = release_params(request.params)
            writer = self._quarantine_writer()
            try:
                fields = writer.read_entry(entry_id)
            except Exception as error:
                raise ReleaseError(f"could not read quarantine entry {entry_id}: "
                                   f"{type(error).__name__}: {error}") from None
            data = check_entry(fields, entry_id, self._name(), digest)
            record = {"time": utc_now(), "reason": request.reason, "requested_by": request.requested_by,
                      "request_sha256": request.sha256, "sha256": digest}
            try:
                claimed = writer.claim_release(entry_id, record)
            except Exception as error:
                raise ReleaseError(f"could not mark entry {entry_id} as released: "
                                   f"{type(error).__name__}: {error}") from None
            if not claimed:
                raise ReleaseError(f"quarantine entry {entry_id} was already released{self._released_when(entry_id)}")
            try:
                target_name, packet_name = self._deliver(data, entry_id)
            except Exception as error:
                self._unclaim(entry_id)
                cause = str(error) if isinstance(error, ReleaseError) else f"{type(error).__name__}: {error}"
                raise ReleaseError(f"quarantine entry {entry_id} was not delivered: {cause}") from None
        except ReleaseError as error:
            return self.record_admin_action("RELEASE", False, str(error), request, entry_id=entry_id)
        self.released += 1
        self.status_due = True
        rule = _field_text(fields, "rule_id") or _field_text(fields, "stage")
        return self.record_admin_action(
            "RELEASE", True, f"released quarantine entry {entry_id} as {target_name} {packet_name} "
            f"(rejected by {rule}); the rules were not checked again", request,
            entry_id=entry_id, sha256=digest, target_name=target_name, packet_name=packet_name,
            apid=_field_text(fields, "apid"), rule_id=_field_text(fields, "rule_id"))

    def _deliver(self, data, entry_id):
        """COSMOS boundary (eaglegate_release.deliver); tests replace it."""
        return deliver(self.interface, data, entry_id, self.scope)

    def _released_when(self, entry_id):
        try:
            previous = self._quarantine_writer().release_record(entry_id) or {}
        except Exception:
            return ""
        who = previous.get("requested_by") or "?"
        return f" at {previous.get('time', '?')} (requested by {who})"

    def _unclaim(self, entry_id):
        try:
            self._quarantine_writer().unclaim_release(entry_id)
        except Exception as error:
            # The entry stays marked released, although it was not delivered: say so
            Logger.error(f"{self._name()} firewall: entry {entry_id} was not delivered but stays marked "
                         f"released ({type(error).__name__}: {error})")

    # ---- status packet -------------------------------------------------------

    def _publish_status_if_due(self, force=False):
        """Publish FIREWALL_STATUS (and FIREWALL_RECENT) when something changed, at
        most once per STATUS_INTERVAL, so a flood of rejections cannot flood
        telemetry too. Runs on the read thread and the ticker thread."""
        with self.publish_lock:
            if self.tick_spike():
                force = True  # the spike state changed: screens and COSMOS limits must see it now
            now = time.monotonic()
            if not force:
                if not (self.status_due or self.recent_due):
                    return
                if self.status_sent_at is not None and now - self.status_sent_at < STATUS_INTERVAL:
                    return
            if self.status is None:
                self.status = StatusPublisher(self.scope, self.target_name)
            self.status_sent_at = now
            # A failed publish stays due, so the screen catches up once publishing works again
            if self.status_due or force:
                self.status_due = not self.status.publish(self.status_items())
            if self.recent_due:
                self._name_recent()
                self.recent_due = not self.status.publish(recent_items(reversed(self.recent)), RECENT_PACKET)

    def tick_spike(self, now=None):
        """Close finished spike windows. Returns True when the state changed.
        `now` (monotonic seconds) is only passed in by tests."""
        closed = self.spike.closed
        change = self.spike.tick(self.ruleset.settings, self.clock() if now is None else now)
        if self.spike.closed != closed:
            self.status_due = True  # REJECT_RATE changed
        if change is None:
            return False
        old, new = change
        info = self.spike.describe()
        if new > old:
            text = f"{self._name()} firewall: rejections {STATE_NAMES[new]}: {info['reason']}"
        else:
            text = f"{self._name()} firewall: rejection spike {STATE_NAMES[new].lower()}: {info['reason']}"
        # A notification (the bell menu), never an alert: the RED SPIKE_STATE already
        # raises COSMOS's alert, and two toasts per spike would train people to dismiss them
        (Logger.error if new == SPIKE else Logger.warn)(text, type=NOTIFICATION)
        self._quarantine_writer().audit({
            "time": utc_now(), "action": "SPIKE", "ok": True, "detail": text,
            "state": STATE_NAMES[new], "previous_state": STATE_NAMES[old],
            "reason": info["reason"], "top": info["top"], "since": info["since"] or "",
        })
        return True

    def _name_recent(self):
        """Name the COSMOS packet of the rejections FIREWALL_RECENT will show, then
        forget their bytes. Only these few, so a flood costs nothing extra."""
        for rejection in list(self.recent)[-RECENT_COUNT:]:
            data = rejection.pop("_data", None)
            if data is not None:
                rejection["packet"] = self._packet_name(data)

    def _packet_name(self, data):
        """"TARGET PACKET" when COSMOS recognises the bytes as telemetry of this
        interface's targets, "unknown" when it does not, "" when it cannot say."""
        try:
            from openc3.system.system import System

            names = list(getattr(self.interface, "tlm_target_names", None) or [])
            if not names:
                return ""
            packet = System.telemetry.identify(data, names)
        except Exception:
            return ""
        return f"{packet.target_name} {packet.packet_name}" if packet else "unknown"

    def _start_ticker(self):
        """A daemon thread that closes spike windows and publishes, so a spike can
        clear (and the screens update) while the link is silent."""
        if not self.TICKER_ENABLED or self.ticker is not None:
            return

        def run():
            while not self.ticker_stop.wait(TICK_SECONDS):
                try:
                    self._publish_status_if_due()
                except Exception as error:  # never let the ticker die silently
                    Logger.error(f"{self._name()} firewall: spike ticker: {type(error).__name__}: {error}")

        self.ticker = threading.Thread(target=run, name=f"eaglegate-ticker-{self._name()}", daemon=True)
        self.ticker.start()

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
            "DENIED_LINK": _u32(self.rejected_by_stage[LINK]),
            "TRUST_RESTORES": _u32(self.trust_restores),
            "RELEASED": _u32(self.released),
            **self.spike.status(),
            "PACKETS": _u32(self.traffic.packets),
            "ALLOWED": _u32(self.traffic.allowed),
            "SEQ_GAPS": _u32(self.traffic.seq_gaps),
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
        warning = interface_warning(self.interface)
        if warning and warning != self.interface_warning:
            Logger.error(f"{self._name()} firewall: {warning}")
        self.interface_warning = warning
        was_untrusted = self.connection_untrusted
        old_ruleset = self.ruleset
        self.first_packet_decided = False  # a new connection gets a fresh start
        self.connection_untrusted = False
        self.untrusted_since = None
        self.untrusted_cause = None
        self.untrusted_captured = 0
        self.connection_id += 1  # counts attempts; only connected ones get quarantine entries
        self.traffic.new_connection()
        self.load_active()
        self._start_ticker()
        # Publish only what screens would see change, not once per retry of a dead link
        if self.status_sent_at is None or was_untrusted or self.ruleset is not old_ruleset:
            self._publish_status_if_due(force=True)

    def protocol_cmd(self, cmd_name, *cmd_args):
        """Called for interface_protocol_cmd("EAGLEGATE_INT", "RELOAD_RULES", ...).

        RELOAD_RULES [base_sha256 [pending_sha256]]: the sha256 of the rule set the
        editor started from, then the sha256 of the pending file it uploaded.
        RESTORE_TRUST <request_sha256> and RELEASE <request_sha256>: see the module docstring.
        Other commands are left to the other protocols (extensions) on the interface."""
        name = str(cmd_name).upper()
        if name == "RESTORE_TRUST":
            self.restore_trust(_optional(cmd_args[0]) if cmd_args else None)
            self.status_due = True  # published by the read thread, like RELOAD_RULES
            return True
        if name == "RELEASE":
            self.release(_optional(cmd_args[0]) if cmd_args else None)
            return True
        if name == "RELOAD_RULES":
            base_sha256, pending_sha256 = (list(map(_optional, cmd_args)) + [None, None])[:2]
            self.apply_pending(base_sha256, pending_sha256)
            # Runs on the interface's command thread: leave publishing the new
            # RULES_VERSION to the read thread, so only one thread writes the packet
            self.status_due = True
            return True
        return False

    def load_active(self):
        """Load the startup rule set: rules_active.json, else the plugin original.
        With signing on, ONLY a correctly signed rules_active.json is loaded.
        Returns True on success; on failure the current rule set stays active."""
        try:
            text, signature = self.store().read_active()
            source = "active"
            if self.signer.enabled:
                self._check_signature(text, signature)
            elif text is None:
                text, source = self.store().read_original(), "original"
            if text is None:
                raise RulesError(f"no rules found: neither {self.store().keys['active']} "
                                 f"nor the plugin's {self.rules_file} exists")
            new_ruleset = parse_rules(text, self._extensions())
            if self.signer.enabled and 0 <= new_ruleset.version < self.ruleset.version:
                # A valid signature on an OLD file: someone put back a previous copy
                raise RulesError(f"{self.store().keys['active']} is version {new_ruleset.version}, older than "
                                 f"the running version {self.ruleset.version}; refusing a rollback. "
                                 "Restore older rules from the EagleGate Firewall page instead")
        except Exception as error:
            return self._rules_failed(error)
        self._swap(new_ruleset, source)
        self.rules_signed = self.signer.enabled
        return True

    def _check_signature(self, text, signature):
        key = self.store().keys["active"]
        if not self.signer.usable:
            raise RulesError(f"rules signing is misconfigured ({self.signer.error}); "
                             "loading no rules until it is fixed")
        if text is None:
            raise RulesError(f"rules signing is on, but there is no signed {key} yet; "
                             "apply the rules from the EagleGate Firewall page to create it")
        if not self.signer.verify(key, text, signature):
            raise RulesError(f"{key} failed its signature check: it was changed outside EagleGate "
                             "(or signed with a different key). Re-apply the rules from the "
                             "EagleGate Firewall page")

    def apply_pending(self, base_sha256=None, pending_sha256=None):
        """Validate rules_pending.json and make it the running and startup set.
        Returns True on success; on failure nothing changes and the error is recorded.
        With no pending file this re-reads the startup set, like a reconnect."""
        try:
            text = self.store().read_pending()
            if text is None:
                return self.load_active()
            if self.signer.enabled and not self.signer.usable:
                # An unsigned active file would be refused at the next restart
                raise RulesError(f"rules signing is misconfigured ({self.signer.error}); cannot apply")
            new_ruleset = parse_rules(text, self._extensions())
            if pending_sha256 and new_ruleset.sha256 != pending_sha256:
                raise RulesError("the pending rules file changed after it was uploaded "
                                 f"(expected sha256 {pending_sha256[:12]}, found {new_ruleset.sha256[:12]}); "
                                 "someone else may be editing the rules, reload and try again")
            if base_sha256 and base_sha256 != self.ruleset.sha256 and new_ruleset.sha256 != self.ruleset.sha256:
                raise RulesError(f"the rules were changed by someone else (you edited sha256 {base_sha256[:12]}, "
                                 f"running is {self.ruleset.sha256[:12]} version {self.ruleset.version}); "
                                 "reload and apply your changes again")
        except Exception as error:
            return self._rules_failed(error)
        signature = self.signer.sign(self.store().keys["active"], text) if self.signer.usable else None
        if self.store().save_active(text, new_ruleset.version, new_ruleset.sha256, signature):
            self.persist_error = None
        else:
            # Running now, but a restart would bring back the previous set: say so loudly
            self.persist_error = f"could not save {self.store().keys['active']}: {self.store().last_error}"
            Logger.error(f"{self._name()} firewall: {self.persist_error}")
        self._swap(new_ruleset, "pending")
        self.rules_signed = signature is not None
        return True

    def _rules_failed(self, error):
        self.rules_error = f"{type(error).__name__}: {error}"
        self.rules_error_at = utc_now()
        Logger.error(
            f"{self._name()} firewall: rules NOT loaded ({self.rules_error}); "
            f"keeping version {self.ruleset.version}"
            + (" (DENY ALL)" if self.ruleset.version < 0 else "")
        )
        return False

    def _swap(self, new_ruleset, source):
        self.rules_error = None
        self.rules_error_at = None
        self.rules_source = source
        if new_ruleset.sha256 == self.ruleset.sha256:
            # Same text: keep the running set, so what the sequence and rate rules
            # remember survives reconnects (a reset would let one replay through)
            return
        old_version = self.ruleset.version
        # A single assignment: read_data sees the old or the new set, never a mix
        self.ruleset = new_ruleset
        # What was normal under the old rules says nothing about the new ones; start
        # strict (more warnings, never fewer), and say so if a spike follows
        self.spike.rules_changed(new_ruleset.version)
        self.rules_loaded_at = utc_now()
        Logger.info(
            f"{self._name()} firewall: rules version {old_version} -> {new_ruleset.version} "
            f"from {source} ({len(new_ruleset.rules)} active rules, sha256 {new_ruleset.sha256[:12]})"
        )

    def _extensions(self):
        """Extensions offered by the protocols BEFORE this one on the interface
        (an extension must see the bytes first). Raises RulesError if one is
        incompatible, which keeps the rules from loading: fail closed."""
        protocols = self.interface.read_protocols if self.interface else []
        before = protocols[:protocols.index(self)] if self in protocols else []
        self.extensions = collect_extensions(before, reserved_sections=TOP_LEVEL_KEYS)
        return self.extensions

    def store(self):
        """The COSMOS storage for the rules. Tests replace it with a fake."""
        if self.rules_store is None:
            self.rules_store = RulesStore(self.scope, self.target_name, self.rules_file)
        return self.rules_store

    # ---- status --------------------------------------------------------------

    def read_details(self):
        """Adds a "firewall" section to interface_details()."""
        result = super().read_details()
        result["firewall"] = {
            "rules_file": self.rules_file,
            "rules_keys": self.store().keys,
            "rules_source": self.rules_source,
            "rules": self.ruleset.summary(),
            "rules_loaded_at": self.rules_loaded_at,
            "rules_error": self.rules_error,
            "rules_error_at": self.rules_error_at,
            "persist_error": self.persist_error,
            "rules_signing": {**self.signer.summary(), "running_signed": self.rules_signed},
            "rejected": self.rejected,
            "rejected_by_stage": dict(self.rejected_by_stage),
            "discarded_bytes": self.discarded_bytes,
            "traffic": self.traffic.describe(),
            "spike": self.spike.describe(),
            "connection_untrusted": self.connection_untrusted,
            "untrusted_since": self.untrusted_since,
            "untrusted_cause": self.untrusted_cause,
            "trust_restores": self.trust_restores,
            "released": self.released,
            "connection_id": self.connection_id,
            "interface_warning": self.interface_warning,
            "api_version": FIREWALL_API_VERSION,
            "settings": dict(self.ruleset.settings),
            # Each extension's rules section and link keys, for the rules page
            "extensions": {section: ext.describe() for section, ext in self.extensions.items()},
            "admin_actions": list(reversed(self.admin_actions)),  # newest first
            "max_length": self.fw_max_length,
            "quarantine": {
                **(self.quarantine.summary() if self.quarantine else {}),
                # newest first; reasons only, no bytes
                "recent": [{k: v for k, v in r.items() if not k.startswith("_")} for r in reversed(self.recent)],
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


def interface_warning(interface):
    """Why EagleGate cannot be administered on this interface, or None.

    COSMOS's TCP server interface gives every connecting client NEW copies of
    the protocols. Those copies filter the data, but protocol commands
    (RELOAD_RULES, RESTORE_TRUST, ...) and interface_details only reach the
    server's own copies, which never see a byte. Use a TCP client or UDP
    interface (or a server that keeps one set of protocols)."""
    if interface is None:
        return None
    kind = type(interface).__name__
    if kind == "TcpipServerInterface":
        return ("runs on a TCP server interface: COSMOS gives each client its own copy of the protocols, "
                "so rule changes, admin commands and these details never reach the copy that filters. "
                "Use a TCP client or UDP interface")
    if kind == "StreamInterface" and interface.name == "StreamInterface":
        return ("runs on a per-client copy made by a TCP server interface: rule changes and admin commands "
                "cannot reach it. Use a TCP client or UDP interface")
    return None


def _optional(arg):
    """interface_protocol_cmd arguments arrive as strings; "", None and "None" mean unset."""
    return None if arg in (None, "", "None", "nil") else str(arg)


def _field_text(fields, name):
    value = (fields or {}).get(name, b"")
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def _u32(count):
    return min(count, 0xFFFFFFFF)


def _apid(data):
    """"APID 0x002" for log lines; raw buffers may be too short for a header."""
    if len(data) < CCSDS_HEADER_BYTES:
        return f"{len(data)} bytes"
    return f"APID 0x{CcsdsHeader.from_bytes(data).apid:03X}"
