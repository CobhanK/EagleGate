"""Admin requests: actions that a COSMOS command alone must not be able to trigger.

interface_protocol_cmd needs only the system_set permission, which operators
often have. So an admin-only action (restoring trust in a connection, an
extension resetting its replay counters, ...) takes two steps, like RELOAD_RULES:

  1. the EagleGate page writes the request to the admin-only config bucket key
     {scope}/eaglegate/{TARGET}/requests/{kind}.json   (eaglegate_rules_store.py
     explains why only admins can write there)
  2. it sends the protocol command with the sha256 of that file, e.g.
     interface_protocol_cmd("EAGLEGATE_INT", "RESTORE_TRUST", "<sha256>")

The firewall acts only when the file exists, is of the right kind, matches the
sha256, is recent, and its nonce was never used. It then deletes the file and
writes an audit entry. An operator who replays the command finds no file, a
used nonce or an expired request.

Request file:
  {
    "kind": "restore_trust",                   # must match the command
    "reason": "spacecraft rebooted at 14:02",   # required, shown in the audit log
    "nonce": "6f1c0e2a-...",                    # 16-64 letters, digits, "-"; new every time
    "requested_at": "2026-11-09T18:00:00Z",     # UTC; refused when older than MAX_AGE
    "requested_by": "alice",                    # informational: COSMOS logs the real user
    "params": {}                                # kind specific, checked by the caller
  }
"""
import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

MAX_AGE = 600         # seconds a request stays valid after requested_at
MAX_CLOCK_SKEW = 60   # seconds requested_at may lie in the future (browser clock)
MAX_REQUEST_BYTES = 8192
REASON_CHARS = 256
USER_CHARS = 64
NONCES_REMEMBERED = 1000
REQUEST_KEYS = {"kind", "reason", "nonce", "requested_at", "requested_by", "params"}
KIND = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
NONCE = re.compile(r"^[A-Za-z0-9-]{16,64}$")
# Printable text only: reasons end up in logs, the audit stream and screens
_UNPRINTABLE = re.compile("[\\x00-\\x1f\\x7f-\\x9f\\u2028\\u2029\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069]")


class RequestError(Exception):
    """Why a request was refused; the message is shown to the admin."""


@dataclass(frozen=True)
class AdminRequest:
    kind: str
    reason: str
    nonce: str
    requested_at: str
    requested_by: str
    sha256: str
    params: dict = field(default_factory=dict)

    def audit_fields(self):
        return {"kind": self.kind, "reason": self.reason, "nonce": self.nonce,
                "requested_at": self.requested_at, "requested_by": self.requested_by,
                "request_sha256": self.sha256}


def parse_request(text, kind, expected_sha256, now=None):
    """Check one request file. Returns an AdminRequest or raises RequestError.
    `now` (a timezone-aware datetime) is only passed in by tests."""
    if text is None:
        raise RequestError(f"no {kind} request has been uploaded (or it was already used)")
    if isinstance(text, str):
        text = text.encode("utf-8")
    if len(text) > MAX_REQUEST_BYTES:
        raise RequestError(f"request is {len(text)} bytes, more than {MAX_REQUEST_BYTES}")
    sha256 = hashlib.sha256(text).hexdigest()
    if not expected_sha256 or sha256 != str(expected_sha256).lower():
        raise RequestError("the request file does not match the command (sha256 differs); "
                           "it was changed or replaced after the page uploaded it")
    try:
        doc = json.loads(text.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RequestError(f"request is not valid JSON: {error}") from None
    if not isinstance(doc, dict):
        raise RequestError("request must be a JSON object")
    unknown = sorted(set(doc) - REQUEST_KEYS)
    if unknown:
        raise RequestError(f"unknown request key(s) {unknown}")
    if doc.get("kind") != kind:
        raise RequestError(f"request is for {doc.get('kind')!r}, not {kind!r}")

    reason = doc.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise RequestError("a reason is required")
    if len(reason) > REASON_CHARS:
        raise RequestError(f"reason is longer than {REASON_CHARS} characters")
    if _UNPRINTABLE.search(reason):
        raise RequestError("reason contains control or invisible characters")

    nonce = doc.get("nonce")
    if not isinstance(nonce, str) or not NONCE.match(nonce):
        raise RequestError("nonce must be 16-64 letters, digits or '-'")

    requested_by = doc.get("requested_by", "")
    if not isinstance(requested_by, str) or len(requested_by) > USER_CHARS or _UNPRINTABLE.search(requested_by):
        raise RequestError(f"requested_by must be printable text of at most {USER_CHARS} characters")

    params = doc.get("params", {})
    if not isinstance(params, dict):
        raise RequestError("params must be an object")

    requested_at = doc.get("requested_at")
    when = _parse_time(requested_at)
    now = now or datetime.now(timezone.utc)
    age = (now - when).total_seconds()
    if age > MAX_AGE:
        raise RequestError(f"request expired: made {int(age)} s ago, the limit is {MAX_AGE} s")
    if age < -MAX_CLOCK_SKEW:
        raise RequestError("request time is in the future; check the browser's clock")

    return AdminRequest(kind=kind, reason=reason.strip(), nonce=nonce, requested_at=requested_at,
                        requested_by=requested_by, sha256=sha256, params=params)


def _parse_time(value):
    if not isinstance(value, str):
        raise RequestError("requested_at must be a UTC time like 2026-11-09T18:00:00Z")
    try:
        when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise RequestError(f"requested_at {value!r} is not a valid time") from None
    if when.tzinfo is None:
        raise RequestError("requested_at must include a time zone (end it with Z for UTC)")
    return when


class NonceLog:
    """Nonces already used, so one uploaded request can never act twice.
    Bounded: requests expire after MAX_AGE, long before the oldest is forgotten."""

    def __init__(self, size=NONCES_REMEMBERED):
        self.order = deque()
        self.seen = set()
        self.size = size

    def use(self, nonce):
        if nonce in self.seen:
            raise RequestError("this request was already used (same nonce); upload a new one")
        self.seen.add(nonce)
        self.order.append(nonce)
        while len(self.order) > self.size:
            self.seen.discard(self.order.popleft())
