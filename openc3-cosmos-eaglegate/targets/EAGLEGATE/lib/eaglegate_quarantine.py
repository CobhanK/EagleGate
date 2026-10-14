"""Where rejected packets go: the quarantine streams and the status packet.

Every rejected packet is written, with the reason, to a capped Valkey stream in
COSMOS's persistent store, so it survives container restarts:

  {scope}__EAGLEGATE__QUARANTINE__{interface}       framed packets denied by the
                                                    rules (RULE, DEFAULT, ERROR);
                                                    whole packets, could later be
                                                    released back into COSMOS
  {scope}__EAGLEGATE__QUARANTINE_RAW__{interface}   bytes that were never framed
                                                    (STRUCTURAL, UNTRUSTED);
                                                    forensics only, never releasable

The raw stream is separate so a flood of garbage cannot push real rule
denials out of the capped quarantine stream.

Planned for the review tool (not written yet; names reserved here):
  {scope}__EAGLEGATE__QUARANTINE_REVIEW__{interface}  hash: entry id -> review state
  {scope}__EAGLEGATE__QUARANTINE_AUDIT__{interface}   stream: who changed what, when

Stream contents are for admins only. The summary packet below (counts and the
last reason, no packet bytes) is ordinary telemetry for operator screens.

Neither class ever raises: a storage problem must not change the firewall's
decision or disconnect the interface. A failed write is counted, and writes are
paused for a while so a Valkey outage does not slow down every rejected packet.
"""
import hashlib
import json
import time
from datetime import datetime, timezone

from eaglegate_ccsds_header import CCSDS_HEADER_BYTES, CcsdsHeader
from eaglegate_verdict import UNTRUSTED

QUARANTINE_MAXLEN = 10000    # framed entries kept; ~10 MB at the default 1024-byte max packet
RAW_MAXLEN = 1000            # raw entries kept
RAW_CAPTURE_BYTES = 4096     # bytes kept per raw entry, and per untrusted connection
PAUSE_AFTER_ERROR = 30.0     # seconds to stop trying after a failed write

STATUS_PACKET = "FIREWALL_STATUS"
STATUS_ID_VERSION = 7  # see FIREWALL_STATUS in cmd_tlm/tlm.txt
# Character limits of the STRING items in FIREWALL_STATUS (bit size / 8)
STATUS_STRING_CHARS = {"LAST_TIME": 32, "LAST_STAGE": 12, "LAST_RULE_ID": 64,
                       "LAST_APID": 8, "LAST_REASON": 256, "LAST_ENTRY_ID": 32}


def stream_names(scope, interface_name):
    base = f"{scope}__EAGLEGATE__QUARANTINE"
    return {
        "quarantine": f"{base}__{interface_name}",
        "raw": f"{base}_RAW__{interface_name}",
        "review": f"{base}_REVIEW__{interface_name}",
        "audit": f"{base}_AUDIT__{interface_name}",
    }


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def header_of(verdict, data):
    """The CCSDS header the bytes start with, or None when they have none.
    Discarded bytes of an untrusted connection are not aligned to packets, so
    a "header" decoded from them would show an APID that was never sent."""
    if verdict.stage == UNTRUSTED or len(data) < CCSDS_HEADER_BYTES:
        return None
    return CcsdsHeader.from_bytes(data)


def entry_fields(verdict, data, interface_name, connection_id, time_text):
    """The stream entry for one rejected packet. Self-contained: the rule's
    description and version are copied in, because the rules file can change
    after the packet was quarantined. Raw bytes are cut to RAW_CAPTURE_BYTES."""
    kept = data if verdict.framed else data[:RAW_CAPTURE_BYTES]
    fields = {
        "time": time_text,
        "interface": interface_name,
        "connection_id": connection_id,
        "stage": verdict.stage,
        "action": verdict.action,
        "rule_id": verdict.rule_id or "",
        "rule_type": verdict.rule_type or "",
        "rule_description": verdict.rule_description,
        "detail": verdict.detail,
        "reason": verdict.reason(),
        "rules_version": "" if verdict.rules_version is None else verdict.rules_version,
        "rules_sha256": verdict.rules_sha256,
        "releasable": "true" if verdict.framed else "false",
        "length": len(data),
        "truncated": "true" if len(kept) < len(data) else "false",
        "sha256": hashlib.sha256(kept).hexdigest(),
        "bytes": bytes(kept),
        "apid": "",
        "seq_count": "",
        "packet_type": "",
    }
    header = header_of(verdict, data)
    if header:
        fields["apid"] = f"0x{header.apid:03X}"
        fields["seq_count"] = header.seq_count
        fields["packet_type"] = "CMD" if header.packet_type else "TLM"
    return fields


class _Guarded:
    """Counts failures and pauses after one, instead of raising."""

    def __init__(self):
        self.errors = 0
        self.last_error = None
        self.paused_until = 0.0

    def _paused(self):
        return time.monotonic() < self.paused_until

    def _failed(self, error):
        self.errors += 1
        self.last_error = f"{type(error).__name__}: {error}"
        self.paused_until = time.monotonic() + PAUSE_AFTER_ERROR


class QuarantineWriter(_Guarded):
    def __init__(self, scope, interface_name):
        super().__init__()
        self.interface_name = interface_name
        self.streams = stream_names(scope, interface_name)
        self.written = 0
        self.skipped = 0  # not attempted because writes were paused

    def record(self, verdict, data, connection_id, time_text):
        """Store one rejected packet. Returns the stream entry id, or None."""
        if self._paused():
            self.skipped += 1
            return None
        if verdict.framed:
            stream, maxlen = self.streams["quarantine"], QUARANTINE_MAXLEN
        else:
            stream, maxlen = self.streams["raw"], RAW_MAXLEN
        try:
            fields = entry_fields(verdict, data, self.interface_name, connection_id, time_text)
            entry_id = self._write(stream, fields, maxlen)
        except Exception as error:
            self._failed(error)
            return None
        self.written += 1
        return entry_id.decode() if isinstance(entry_id, bytes) else str(entry_id)

    def _write(self, stream, fields, maxlen):
        """XADD with MAXLEN ~maxlen. Separate method so tests need no Valkey."""
        from openc3.utilities.store import Store

        return Store.instance().write_topic(stream, fields, maxlen=maxlen, approximate=True)

    def summary(self):
        return {
            "streams": {"quarantine": self.streams["quarantine"], "raw": self.streams["raw"]},
            "written": self.written,
            "errors": self.errors,
            "skipped": self.skipped,
            "last_error": self.last_error,
        }


class StatusPublisher(_Guarded):
    """Publishes the FIREWALL_STATUS telemetry packet.

    Uses the same function the interface microservice runs for inject_tlm, but
    calls it directly: the packet is written to the telemetry stream at once,
    and nothing waits for an acknowledgement on the interface's read thread."""

    def __init__(self, scope, target_name):
        super().__init__()
        self.scope = scope
        self.target_name = target_name
        self.published = 0

    def publish(self, items):
        """items: FIREWALL_STATUS item name -> converted value."""
        if self._paused():
            return False
        message = {
            "target_name": self.target_name,
            "packet_name": STATUS_PACKET,
            "item_hash": status_items(items),
            "type": "CONVERTED",
        }
        try:
            self._inject(json.dumps(message))
        except Exception as error:
            self._failed(error)
            return False
        self.published += 1
        return True

    def _inject(self, message_json):
        """Separate method so tests need no COSMOS runtime."""
        from openc3.microservices.interface_decom_common import handle_inject_tlm

        handle_inject_tlm(message_json, self.scope)


def status_items(items):
    """Add the ID value and cut strings to fit their items."""
    result = {"CCSDS_VERSION": STATUS_ID_VERSION, **items}
    for name, chars in STATUS_STRING_CHARS.items():
        if name in result:
            text = str(result[name]).encode("utf-8")[:chars]
            result[name] = text.decode("utf-8", "ignore")  # never split a character
    return result
