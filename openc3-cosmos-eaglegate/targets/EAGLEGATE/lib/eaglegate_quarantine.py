"""Where rejected packets go: the quarantine streams and the status packet.

Every rejected packet is written, with the reason, to a capped Valkey stream in
COSMOS's persistent store, so it survives container restarts:

  {scope}__EAGLEGATE__QUARANTINE__{interface}       framed packets denied by the
                                                    rules (RULE, DEFAULT, ERROR);
                                                    whole packets, could later be
                                                    released back into COSMOS
  {scope}__EAGLEGATE__QUARANTINE_RAW__{interface}   bytes that were never framed
                                                    (STRUCTURAL, UNTRUSTED) and
                                                    link-layer rejections (LINK,
                                                    e.g. a whole transfer frame);
                                                    forensics only, never releasable
  {scope}__EAGLEGATE__QUARANTINE_AUDIT__{interface} admin actions (restore trust,
                                                    extension resets, reviews,
                                                    releases): who asked, why,
                                                    and what happened
  {scope}__EAGLEGATE__QUARANTINE_REVIEW__{interface}   hash: entry id -> review
                                                    state (written by the review
                                                    microservice)
  {scope}__EAGLEGATE__QUARANTINE_RELEASED__{interface} hash: entry id -> release
                                                    record (written only by the
                                                    firewall, at most once per entry)

The raw stream is separate so a flood of garbage cannot push real rule
denials out of the capped quarantine stream.

Stream contents are for admins only: the review microservice
(microservices/EAGLEGATE_QUARANTINE) asks the COSMOS server whether the caller
is an admin before it shows any. The summary packet below (counts and the last
reason, no packet bytes) is ordinary telemetry for operator screens.

Neither class ever raises: a storage problem must not change the firewall's
decision or disconnect the interface. A failed write is counted, and writes are
paused for a while so a Valkey outage does not slow down every rejected packet.
"""
import hashlib
import json
import time
from datetime import datetime, timezone

from eaglegate_ccsds_header import CCSDS_HEADER_BYTES, CcsdsHeader
from eaglegate_verdict import LINK, UNTRUSTED

# Defaults of the retention settings (rules file settings.quarantine_*, audit_max_entries;
# decision C14). An admin can change them on the Rules tab.
QUARANTINE_MAXLEN = 10000    # framed entries kept; ~10 MB at the default 1024-byte max packet
RAW_MAXLEN = 1000            # raw entries kept
RAW_CAPTURE_BYTES = 4096     # bytes kept per raw entry, and per untrusted connection
AUDIT_MAXLEN = 10000         # admin actions kept
RETENTION_DEFAULTS = {
    "quarantine_max_entries": QUARANTINE_MAXLEN,
    "quarantine_raw_max_entries": RAW_MAXLEN,
    "quarantine_raw_capture_bytes": RAW_CAPTURE_BYTES,
    "quarantine_max_age_days": 0,   # 0 = no age limit, only the entry counts
    "audit_max_entries": AUDIT_MAXLEN,
}
TRIM_INTERVAL = 60.0         # seconds between age trims (XTRIM MINID) of the two streams
PAUSE_AFTER_ERROR = 30.0     # seconds to stop trying after a failed write

STATUS_PACKET = "FIREWALL_STATUS"
STATUS_ID_VERSION = 7  # see FIREWALL_STATUS in cmd_tlm/tlm.txt
# Character limits of the STRING items in FIREWALL_STATUS (bit size / 8)
STATUS_STRING_CHARS = {"LAST_TIME": 32, "LAST_STAGE": 12, "LAST_RULE_ID": 64,
                       "LAST_APID": 8, "LAST_REASON": 256, "LAST_ENTRY_ID": 32,
                       "SPIKE_REASON": 256, "SPIKE_TOP_RULE": 64, "SPIKE_SINCE": 32}

# The last rejections as operator telemetry, for the FIREWALLREJECTIONS widget
# (decision C9): no packet bytes, text cleaned (eaglegate_safe_text.py)
RECENT_PACKET = "FIREWALL_RECENT"
RECENT_ID_VERSION = 5  # see FIREWALL_RECENT in cmd_tlm/tlm.txt
RECENT_COUNT = 10
RECENT_JSON_BYTES = 4000  # the RECENT_JSON item is variable length; keep it bounded
RECENT_REASON_CHARS = 160


def stream_names(scope, interface_name):
    base = f"{scope}__EAGLEGATE__QUARANTINE"
    return {
        "quarantine": f"{base}__{interface_name}",
        "raw": f"{base}_RAW__{interface_name}",
        "review": f"{base}_REVIEW__{interface_name}",
        "audit": f"{base}_AUDIT__{interface_name}",
        "released": f"{base}_RELEASED__{interface_name}",
    }


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def header_of(verdict, data):
    """The CCSDS header the bytes start with, or None when they have none.
    Discarded bytes of an untrusted connection are not aligned to packets, so
    a "header" decoded from them would show an APID that was never sent, and
    LINK rejections hold link-layer bytes (a frame), not a packet."""
    if verdict.stage in (UNTRUSTED, LINK) or len(data) < CCSDS_HEADER_BYTES:
        return None
    return CcsdsHeader.from_bytes(data)


def entry_fields(verdict, data, interface_name, connection_id, time_text, link=None,
                 raw_capture_bytes=RAW_CAPTURE_BYTES):
    """The stream entry for one rejected packet. Self-contained: the rule's
    description and version are copied in, because the rules file can change
    after the packet was quarantined. Raw bytes are cut to raw_capture_bytes.
    `link`: what an extension knew about the link (e.g. the virtual channel)."""
    kept = data if verdict.framed else data[:raw_capture_bytes]
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
        "releasable": "true" if verdict.releasable else "false",
        "monitor": "true" if verdict.monitor else "false",  # delivered; recorded only
        "length": len(data),
        "truncated": "true" if len(kept) < len(data) else "false",
        "sha256": hashlib.sha256(kept).hexdigest(),
        "bytes": bytes(kept),
        "apid": "",
        "seq_count": "",
        "packet_type": "",
        "layer": verdict.layer,
        "link": json.dumps(link, sort_keys=True) if link else "",
    }
    header = header_of(verdict, data)
    if header:
        fields["apid"] = f"0x{header.apid:03X}"
        fields["seq_count"] = header.seq_count
        fields["packet_type"] = "CMD" if header.packet_type else "TLM"
    return fields


def _stream_value(value):
    """Valkey stream fields hold strings, bytes and numbers only."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True)
    return value


def _text(value):
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


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
        self.audited = 0
        self.settings = dict(RETENTION_DEFAULTS)  # the running rules' settings (the firewall keeps it current)
        self.trimmed_at = None  # monotonic time of the last age trim
        self.trims = 0

    def limit(self, name):
        return self.settings.get(name, RETENTION_DEFAULTS[name])

    @property
    def raw_capture_bytes(self):
        return self.limit("quarantine_raw_capture_bytes")

    def record(self, verdict, data, connection_id, time_text, link=None):
        """Store one rejected packet. Returns the stream entry id, or None."""
        if self._paused():
            self.skipped += 1
            return None
        if verdict.framed:
            stream, maxlen = self.streams["quarantine"], self.limit("quarantine_max_entries")
        else:
            stream, maxlen = self.streams["raw"], self.limit("quarantine_raw_max_entries")
        try:
            fields = entry_fields(verdict, data, self.interface_name, connection_id, time_text, link,
                                  self.raw_capture_bytes)
            entry_id = self._write(stream, fields, maxlen)
            self._trim_by_age()
        except Exception as error:
            self._failed(error)
            return None
        self.written += 1
        return entry_id.decode() if isinstance(entry_id, bytes) else str(entry_id)

    def audit(self, fields):
        """Store one admin action in the audit stream. Unlike rejections, this is
        tried even while writes are paused: an admin action is rare and its record
        matters more. Returns the entry id, or None."""
        try:
            entry = {"interface": self.interface_name, **{k: _stream_value(v) for k, v in fields.items()}}
            entry_id = self._write(self.streams["audit"], entry, self.limit("audit_max_entries"))
        except Exception as error:
            self._failed(error)
            return None
        self.audited += 1
        return entry_id.decode() if isinstance(entry_id, bytes) else str(entry_id)

    def _trim_by_age(self, now=None, wall=None):
        """With quarantine_max_age_days set, drop entries older than that from both
        streams (XTRIM MINID ~), at most once per TRIM_INTERVAL. The audit
        stream is only capped by count: it is the record of what admins did."""
        days = self.limit("quarantine_max_age_days")
        now = time.monotonic() if now is None else now
        if not days or (self.trimmed_at is not None and now - self.trimmed_at < TRIM_INTERVAL):
            return
        self.trimmed_at = now
        cutoff_ms = int(((time.time() if wall is None else wall) - days * 86400) * 1000)
        for name in ("quarantine", "raw"):
            self._trim(self.streams[name], f"{max(cutoff_ms, 0)}-0")
        self.trims += 1

    # ---- release (eaglegate_release.py); these may raise, the caller reports it ----

    def read_entry(self, entry_id):
        """The fields of one entry of the FRAMED quarantine stream, as
        {str: bytes}, or None when it does not exist (never written, or trimmed).
        Raw entries are never read here: they can never be released."""
        found = self._range(self.streams["quarantine"], entry_id)
        if not found:
            return None
        _, fields = found[0]
        return {_text(k): v for k, v in fields.items()}

    def claim_release(self, entry_id, record):
        """Mark an entry released, atomically (HSETNX): True for the first
        caller only, so one entry can never be released twice."""
        return bool(self._hsetnx(self.streams["released"], entry_id, json.dumps(record, sort_keys=True)))

    def release_record(self, entry_id):
        """The stored release record of an entry (dict), or None."""
        value = self._hget(self.streams["released"], entry_id)
        return json.loads(_text(value)) if value else None

    def unclaim_release(self, entry_id):
        """Undo claim_release when the packet could not be delivered."""
        self._hdel(self.streams["released"], entry_id)

    # ---- COSMOS boundary: separate methods so tests need no Valkey ----------

    def _write(self, stream, fields, maxlen):
        """XADD with MAXLEN ~maxlen."""
        from openc3.utilities.store import Store

        return Store.instance().write_topic(stream, fields, maxlen=maxlen, approximate=True)

    def _trim(self, stream, minid):
        from openc3.utilities.store import Store

        return Store.instance().trim_topic(stream, minid, approximate=True)

    def _range(self, stream, entry_id):
        from openc3.utilities.store import Store

        return Store.instance().xrange(stream, entry_id, entry_id, count=1)

    def _hsetnx(self, key, field, value):
        from openc3.utilities.store import Store

        return Store.instance().hsetnx(key, field, value)

    def _hget(self, key, field):
        from openc3.utilities.store import Store

        return Store.instance().hget(key, field)

    def _hdel(self, key, field):
        from openc3.utilities.store import Store

        return Store.instance().hdel(key, field)

    def summary(self):
        return {
            "streams": {"quarantine": self.streams["quarantine"], "raw": self.streams["raw"],
                        "audit": self.streams["audit"], "review": self.streams["review"],
                        "released": self.streams["released"]},
            "audited": self.audited,
            "retention": {name: self.limit(name) for name in RETENTION_DEFAULTS},
            "age_trims": self.trims,
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

    def publish(self, items, packet_name=STATUS_PACKET):
        """items: item name -> converted value, of FIREWALL_STATUS (completed by
        status_items()) or of FIREWALL_RECENT (made by recent_items())."""
        if self._paused():
            return False
        message = {
            "target_name": self.target_name,
            "packet_name": packet_name,
            "item_hash": status_items(items) if packet_name == STATUS_PACKET else items,
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


def recent_items(rejections):
    """FIREWALL_RECENT items from the newest-first rejection summaries the
    firewall keeps (eaglegate_firewall_protocol._quarantine). Reasons are cut
    shorter until the JSON fits RECENT_JSON_BYTES."""
    from eaglegate_safe_text import clean

    source = list(rejections)[:RECENT_COUNT]
    rows = []
    for r in source:
        rows.append({
            "time": clean(r.get("time"), 32),
            "interface": clean(r.get("interface"), 64),
            "stage": clean(r.get("stage"), 12),
            "rule_id": clean(r.get("rule_id") or "", 64),
            "rule_type": clean(r.get("rule_type") or "", 32),
            "monitor": bool(r.get("monitor")),
            "layer": clean(r.get("layer") or "", 32),
            "apid": clean(r.get("apid") or "", 8),
            "packet_type": clean(r.get("packet_type") or "", 3),
            "packet": clean(r.get("packet") or "", 80),
            "seq_count": r.get("seq_count") if isinstance(r.get("seq_count"), int) else None,
            "length": r.get("length") if isinstance(r.get("length"), int) else None,
            "link": {clean(k, 32): clean(v, 64) for k, v in list((r.get("link") or {}).items())[:8]},
            "reason": r.get("reason") or "",
            "entry_id": clean(r.get("entry_id") or "", 32),
        })
    limit = RECENT_REASON_CHARS
    while True:
        for row, r in zip(rows, source):
            row["reason"] = clean(r.get("reason") or "", limit)
        text = json.dumps(rows, ensure_ascii=True, separators=(",", ":"))
        if len(text) <= RECENT_JSON_BYTES or limit <= 16:
            break
        limit //= 2
    while len(text) > RECENT_JSON_BYTES and rows:  # only with absurdly long names
        rows.pop()
        text = json.dumps(rows, ensure_ascii=True, separators=(",", ":"))
    return {"CCSDS_VERSION": RECENT_ID_VERSION, "RECENT_COUNT": len(rows), "RECENT_JSON": text}
