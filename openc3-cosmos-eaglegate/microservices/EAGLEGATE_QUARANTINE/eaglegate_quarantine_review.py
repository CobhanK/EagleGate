"""Reading and reviewing the quarantine, for the review microservice.

Pure logic: no HTTP and no COSMOS imports. `store` is anything with the
redis-py stream and hash methods (COSMOS's Store.instance(), or a fake in the
tests). eaglegate_quarantine_service.py puts HTTP and the admin check around it.

What a viewer receives is SAFE TO DISPLAY (decision C7 in EagleGate/DECISIONS.md):
  * packet bytes only as lowercase hex, never as text
  * every text field (reasons, rule descriptions, link values: some of it
    comes from the packet itself) as printable text: control, format and
    invisible characters (bidi overrides, zero-width, line separators) are
    replaced by visible escapes like \\x1b or \\u202e, and long text is cut
  * no expected MACs or keys (the firewall never stores them)
The page escapes again when it renders (Vue text interpolation, never v-html).

Keys, per interface (the firewall's eaglegate_quarantine.stream_names; a test
keeps the two in step):
  {scope}__EAGLEGATE__QUARANTINE__{iface}           framed rejections (stream)
  {scope}__EAGLEGATE__QUARANTINE_RAW__{iface}       raw rejections (stream)
  {scope}__EAGLEGATE__QUARANTINE_REVIEW__{iface}    "{stream}:{entry id}" -> review JSON (hash)
  {scope}__EAGLEGATE__QUARANTINE_RELEASED__{iface}  entry id -> release JSON (hash, firewall only)
  {scope}__EAGLEGATE__QUARANTINE_AUDIT__{iface}     admin actions (stream)
"""
import json
import re
from datetime import datetime, timezone

STREAMS = ("quarantine", "raw")
STAGES = ("RULE", "DEFAULT", "ERROR", "STRUCTURAL", "UNTRUSTED", "LINK")
# Review states an admin can set. "new" clears the review; "released" is set
# only by the firewall's RELEASE (the RELEASED hash), never here.
REVIEW_STATES = ("new", "reviewed", "false_positive", "threat", "dismissed")
REVIEW_FILTERS = REVIEW_STATES + ("released",)

DEFAULT_LIMIT = 50
MAX_LIMIT = 1000
SCAN_BATCH = 500
MAX_SCAN = 10000         # the framed stream's cap (QUARANTINE_MAXLEN): one request may read it all
MAX_REVIEW_IDS = 200     # entries one review request may change
REVIEW_KEEP = 25000      # review hash fields kept before pruning those of trimmed entries
AUDIT_MAXLEN = 10000
TEXT_CHARS = 512         # most characters of one text field sent to the page
REASON_CHARS = 1024
NOTE_CHARS = 256
USER_CHARS = 64
SEARCH_CHARS = 100
RULE_ID_CHARS = 64

ENTRY_ID = re.compile(r"^[0-9]{1,20}-[0-9]{1,20}$")
NAME = re.compile(r"^[A-Za-z0-9_]{1,64}$")  # COSMOS scope and interface names
# Characters that are invisible or change how text around them looks
UNSAFE = re.compile("[\\x00-\\x1f\\x7f-\\x9f\\u00ad\\u061c\\u180e\\u2028\\u2029\\u200b-\\u200f"
                    "\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff\\ufff9-\\ufffb]")
TEXT_FIELDS = ("time", "interface", "stage", "action", "rule_id", "rule_type", "rule_description",
               "detail", "rules_sha256", "sha256", "apid", "packet_type", "layer")


class QueryError(ValueError):
    """A request the service refuses (HTTP 400); the message is shown to the admin."""


def keys(scope, interface):
    base = f"{scope}__EAGLEGATE__QUARANTINE"
    return {
        "quarantine": f"{base}__{interface}",
        "raw": f"{base}_RAW__{interface}",
        "review": f"{base}_REVIEW__{interface}",
        "released": f"{base}_RELEASED__{interface}",
        "audit": f"{base}_AUDIT__{interface}",
    }


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---- making text safe to show --------------------------------------------------

def _escape(match):
    code = ord(match.group(0))
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def clean(value, limit=TEXT_CHARS):
    """Printable text: bytes decoded as UTF-8 (bad bytes become U+FFFD), unsafe
    characters escaped, cut to `limit` characters."""
    if value is None:
        return ""
    text = value.decode("utf-8", "replace") if isinstance(value, (bytes, bytearray)) else str(value)
    text = UNSAFE.sub(_escape, text)
    return text if len(text) <= limit else text[:limit] + "…"


def clean_json(value, depth=0):
    """A parsed JSON value with every string (keys too) cleaned."""
    if depth > 4:
        return clean(json.dumps(value))
    if isinstance(value, dict):
        return {clean(k, 64): clean_json(v, depth + 1) for k, v in list(value.items())[:32]}
    if isinstance(value, list):
        return [clean_json(v, depth + 1) for v in value[:32]]
    if isinstance(value, str):
        return clean(value, 128)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return clean(str(value), 128)


def _str(fields, name):
    value = fields.get(name, b"")
    return value.decode("utf-8", "replace") if isinstance(value, (bytes, bytearray)) else str(value)


def _int(fields, name):
    try:
        return int(_str(fields, name))
    except ValueError:
        return None


def _decode_fields(fields):
    return {(k.decode("utf-8", "replace") if isinstance(k, bytes) else str(k)): v for k, v in fields.items()}


def _json_or_none(value):
    if not value:
        return None
    try:
        parsed = json.loads(value.decode("utf-8", "replace") if isinstance(value, bytes) else value)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def summary(entry_id, fields, stream, review=None, released=None):
    """One entry as the list shows it: metadata and reason, no bytes."""
    fields = _decode_fields(fields)
    view = {"id": clean(entry_id, 48), "stream": stream}
    for name in TEXT_FIELDS:
        view[name] = clean(fields.get(name, b""))
    view["reason"] = clean(fields.get("reason", b""), REASON_CHARS)
    view["connection_id"] = _int(fields, "connection_id")
    view["rules_version"] = _int(fields, "rules_version")
    view["length"] = _int(fields, "length")
    view["seq_count"] = _int(fields, "seq_count")
    view["releasable"] = _str(fields, "releasable") == "true" and stream == "quarantine"
    view["truncated"] = _str(fields, "truncated") == "true"
    link = _json_or_none(fields.get("link"))
    view["link"] = clean_json(link) if link else None
    view["review"] = _clean_record(review)
    view["released"] = _clean_record(released)
    view["review_state"] = "released" if view["released"] else (view["review"] or {}).get("state", "new")
    return view


def detail(entry_id, fields, stream, review=None, released=None):
    """One entry with its bytes, as hex."""
    view = summary(entry_id, fields, stream, review, released)
    data = _decode_fields(fields).get("bytes", b"")
    if isinstance(data, str):
        data = data.encode("latin-1", "replace")
    view["bytes_hex"] = bytes(data).hex()
    view["bytes_kept"] = len(data)
    return view


def _clean_record(value):
    record = _json_or_none(value)
    return clean_json(record) if record else None


# ---- request parameters --------------------------------------------------------

def _printable(text, what, limit):
    if not isinstance(text, str):
        raise QueryError(f"{what} must be text")
    if len(text) > limit:
        raise QueryError(f"{what} is longer than {limit} characters")
    if UNSAFE.search(text):
        raise QueryError(f"{what} contains control or invisible characters")
    return text


def name_param(value, what):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise QueryError(f"{what} must be 1-64 letters, digits or '_'")
    return value


def stream_param(value):
    value = value or "quarantine"
    if value not in STREAMS:
        raise QueryError(f"stream must be one of {', '.join(STREAMS)}")
    return value


def entry_id_param(value, what="id"):
    if not isinstance(value, str) or not ENTRY_ID.fullmatch(value):
        raise QueryError(f"{what} must be a stream entry id like 1731700000000-0")
    return value


def list_query(params):
    """Checked list filters from the query string (a dict of strings)."""
    def get(name):
        return (params.get(name) or "").strip()

    try:
        limit = int(get("limit") or DEFAULT_LIMIT)
    except ValueError:
        raise QueryError("limit must be a whole number") from None
    if not 1 <= limit <= MAX_LIMIT:
        raise QueryError(f"limit must be 1 to {MAX_LIMIT}")
    query = {"limit": limit, "stream": stream_param(get("stream"))}
    stage = get("stage").upper()
    if stage and stage not in STAGES:
        raise QueryError(f"stage must be one of {', '.join(STAGES)}")
    query["stage"] = stage
    query["rule_id"] = _printable(get("rule_id"), "rule_id", RULE_ID_CHARS)
    apid = get("apid")
    if apid:
        try:
            number = int(apid, 0)
        except ValueError:
            raise QueryError("apid must be a number such as 0x01A or 26") from None
        if not 0 <= number <= 0x7FF:
            raise QueryError("apid must be 0 to 0x7FF")
        apid = f"0x{number:03X}"
    query["apid"] = apid
    review = get("review")
    if review and review not in REVIEW_FILTERS:
        raise QueryError(f"review must be one of {', '.join(REVIEW_FILTERS)}")
    query["review"] = review
    query["search"] = _printable(get("search"), "search", SEARCH_CHARS).lower()
    before = get("before")
    query["before"] = entry_id_param(before, "before") if before else ""
    return query


def matches(view, query):
    if query["stage"] and view["stage"] != query["stage"]:
        return False
    if query["rule_id"] and view["rule_id"] != query["rule_id"]:
        return False
    if query["apid"] and view["apid"] != query["apid"]:
        return False
    if query["review"] and view["review_state"] != query["review"]:
        return False
    if query["search"]:
        haystack = " ".join((view["reason"], view["detail"], view["rule_description"],
                             view["rule_id"], view["apid"], view["id"])).lower()
        if query["search"] not in haystack:
            return False
    return True


def review_body(body):
    """Checked review request: (stream, ids, state, note, requested_by)."""
    if not isinstance(body, dict):
        raise QueryError("the request body must be a JSON object")
    unknown = sorted(set(body) - {"interface", "stream", "ids", "state", "note", "requested_by"})
    if unknown:
        raise QueryError(f"unknown field(s) {unknown}")
    stream = stream_param(body.get("stream"))
    ids = body.get("ids")
    if not isinstance(ids, list) or not ids:
        raise QueryError("ids must be a non-empty list of entry ids")
    if len(ids) > MAX_REVIEW_IDS:
        raise QueryError(f"at most {MAX_REVIEW_IDS} entries per review")
    ids = list(dict.fromkeys(entry_id_param(i) for i in ids))
    state = body.get("state")
    if state not in REVIEW_STATES:
        raise QueryError(f"state must be one of {', '.join(REVIEW_STATES)} (releasing is a separate action)")
    note = _printable(body.get("note", ""), "note", NOTE_CHARS).strip()
    requested_by = _printable(body.get("requested_by", ""), "requested_by", USER_CHARS)
    return stream, ids, state, note, requested_by


# ---- reading -------------------------------------------------------------------

def _hmget(store, key, fields):
    return dict(zip(fields, store.hmget(key, fields))) if fields else {}


def list_entries(store, k, query):
    """The newest `limit` entries of one stream that match the filters, newest
    first. Reads back from `before` (exclusive) in batches, at most MAX_SCAN
    entries per request. `next_before` continues an unfinished scan."""
    stream = query["stream"]
    upper = f"({query['before']}" if query["before"] else "+"
    found, scanned, last_id, exhausted = [], 0, None, False
    while len(found) < query["limit"] and scanned < MAX_SCAN:
        requested = min(SCAN_BATCH, MAX_SCAN - scanned)
        batch = store.xrevrange(k[stream], upper, "-", count=requested)
        if not batch:
            exhausted = True
            break
        ids = [_str({"i": i}, "i") for i, _ in batch]
        reviews = _hmget(store, k["review"], [f"{stream}:{i}" for i in ids])
        released = _hmget(store, k["released"], ids) if stream == "quarantine" else {}
        for entry_id, (_, fields) in zip(ids, batch):
            scanned += 1
            last_id = entry_id
            view = summary(entry_id, fields, stream, reviews.get(f"{stream}:{entry_id}"), released.get(entry_id))
            if matches(view, query):
                found.append(view)
                if len(found) == query["limit"]:
                    break
        upper = f"({last_id}"
        if len(batch) < requested and len(found) < query["limit"]:
            exhausted = True
            break
    return {
        "stream": stream,
        "entries": found,
        "scanned": scanned,
        "stream_length": store.xlen(k[stream]),
        "next_before": None if exhausted else last_id,
    }


def get_entry(store, k, stream, entry_id):
    """One entry with its bytes, or None."""
    found = store.xrange(k[stream], entry_id, entry_id, count=1)
    if not found:
        return None
    _, fields = found[0]
    review = store.hget(k["review"], f"{stream}:{entry_id}")
    released = store.hget(k["released"], entry_id) if stream == "quarantine" else None
    return detail(entry_id, fields, stream, review, released)


# ---- reviewing -----------------------------------------------------------------

def set_review(store, k, interface, stream, ids, state, note, user, requested_by):
    """Set (or with "new", clear) the review state of entries that exist.
    Writes one audit entry. Returns {"updated": [...], "missing": [...], "audit_id"}."""
    present = [i for i in ids if store.xrange(k[stream], i, i, count=1)]
    missing = [i for i in ids if i not in present]
    if not present:
        raise QueryError("none of these entries exist any more (the stream is capped)")
    fields = [f"{stream}:{i}" for i in present]
    if state == "new":
        store.hdel(k["review"], *fields)
    else:
        record = json.dumps({"state": state, "note": note, "user": user, "requested_by": requested_by,
                             "at": utc_now()}, sort_keys=True)
        for field in fields:
            store.hset(k["review"], field, record)
    audit = {
        "time": utc_now(), "action": "REVIEW", "ok": "true", "interface": interface, "stream": stream,
        "state": state, "note": note, "user": user, "requested_by": requested_by,
        "entry_ids": json.dumps(present[:50]), "count": len(present),
        "detail": f"{len(present)} {stream} entr{'y' if len(present) == 1 else 'ies'} set to {state}",
    }
    audit_id = store.xadd(k["audit"], audit, maxlen=AUDIT_MAXLEN, approximate=True)
    prune_reviews(store, k)
    return {"updated": present, "missing": missing,
            "audit_id": audit_id.decode() if isinstance(audit_id, bytes) else audit_id}


def prune_reviews(store, k):
    """Drop review fields of entries the capped streams no longer hold."""
    if store.hlen(k["review"]) <= REVIEW_KEEP:
        return 0
    oldest = {}
    for stream in STREAMS:
        first = store.xrange(k[stream], "-", "+", count=1)
        oldest[stream] = _id_tuple(_str({"i": first[0][0]}, "i")) if first else None
    stale = []
    for field in store.hkeys(k["review"]):
        name = field.decode() if isinstance(field, bytes) else str(field)
        stream, _, entry_id = name.partition(":")
        floor = oldest.get(stream)
        if floor is None or not ENTRY_ID.fullmatch(entry_id) or _id_tuple(entry_id) < floor:
            stale.append(field)
    for start in range(0, len(stale), 500):
        store.hdel(k["review"], *stale[start:start + 500])
    return len(stale)


def _id_tuple(entry_id):
    ms, _, seq = entry_id.partition("-")
    return int(ms), int(seq or 0)
