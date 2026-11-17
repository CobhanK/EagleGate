"""The quarantine review microservice (microservices/EAGLEGATE_QUARANTINE):
admin-only access decided by the COSMOS server, listing and filtering,
safe-to-display output, and review states (decisions C5, C7)."""
import base64
import itertools
import json
import os
import sys
import urllib.error

import pytest
from conftest import ROOT, ccsds, status_3
from eaglegate_quarantine import entry_fields, stream_names
from eaglegate_verdict import RULE, STRUCTURAL, Verdict
from fake_store import FakeStore

sys.path.insert(0, os.path.join(ROOT, "microservices", "EAGLEGATE_QUARANTINE"))

import eaglegate_quarantine_review as review
import eaglegate_quarantine_service as service

SCOPE, IFACE = "DEFAULT", "EAGLEGATE_INT"
K = review.keys(SCOPE, IFACE)


def store_rejection(store, data, stage=RULE, rule_id="deny-3", detail="no rule allows APID 3", **verdict):
    v = Verdict(action="DENY", stage=stage, detail=detail, rule_id=rule_id if stage == RULE else None,
                rule_type="match" if stage == RULE else None, rules_version=4, rules_sha256="ab" * 32, **verdict)
    stream = K["quarantine"] if v.framed else K["raw"]
    return store.xadd(stream, entry_fields(v, data, IFACE, 1, "2026-11-16T12:00:00.000000Z")).decode()


# ---- keys and safety -------------------------------------------------------------

def test_key_names_match_the_firewall():
    names = stream_names(SCOPE, IFACE)
    assert {k: K[k] for k in names} == names


@pytest.mark.parametrize("text, shown", [
    ("plain text", "plain text"),
    ("\x1b[31mred\x1b[0m", "\\x1b[31mred\\x1b[0m"),        # terminal escape
    ("abc\u202edcba", "abc\\u202edcba"),                     # right-to-left override
    ("zero\u200bwidth", "zero\\u200bwidth"),
    ("line break\nnew", "line\\u2028break\\x0anew"),
    (b"\xff\xfe<script>", "��<script>"),          # bad UTF-8; markup left to the page to escape
])
def test_clean_makes_text_printable(text, shown):
    assert review.clean(text) == shown


def test_clean_cuts_long_text():
    assert review.clean("x" * 600) == "x" * review.TEXT_CHARS + "…"


def test_packet_text_in_a_reason_is_shown_escaped():
    store = FakeStore()
    entry_id = store_rejection(store, status_3(), detail="field NAME = 'evil\x07\u202e'")
    view = review.get_entry(store, K, "quarantine", entry_id)
    assert "\x07" not in json.dumps(view, ensure_ascii=False) and "\u202e" not in view["detail"]
    assert view["detail"] == "field NAME = 'evil\\x07\\u202e'"


def test_detail_has_the_bytes_only_as_hex():
    store = FakeStore()
    data = ccsds(3, b"\x00ABC\x1b\xff")
    entry_id = store_rejection(store, data)
    view = review.get_entry(store, K, "quarantine", entry_id)
    assert view["bytes_hex"] == data.hex() and view["bytes_kept"] == len(data)
    assert (view["apid"], view["seq_count"], view["packet_type"], view["length"]) == ("0x003", 0, "TLM", len(data))
    assert view["releasable"] is True and view["review_state"] == "new"
    listed = review.list_entries(store, K, review.list_query({}))["entries"][0]
    assert "bytes_hex" not in listed and "bytes" not in listed


def test_link_values_are_cleaned():
    store = FakeStore()
    v = Verdict(action="DENY", stage="LINK", detail="frame", layer="frame", rules_version=1)
    store.xadd(K["raw"], entry_fields(v, b"\x01\x02", IFACE, 1, "t", link={"vcid": 4, "note\x1b": "a\u202eb"}))
    [entry] = review.list_entries(store, K, review.list_query({"stream": "raw"}))["entries"]
    assert entry["link"] == {"vcid": 4, "note\\x1b": "a\\u202eb"} and entry["releasable"] is False


# ---- listing and filtering --------------------------------------------------------

def many(store, n=30):
    ids = []
    for i in range(n):
        apid = 3 if i % 2 else 4
        ids.append(store_rejection(store, ccsds(apid, bytes(4), seq=i), rule_id=f"deny-{apid}",
                                   detail=f"packet number {i}"))
    return ids


def test_newest_first_with_a_user_limit():
    store = FakeStore()
    ids = many(store)
    result = review.list_entries(store, K, review.list_query({"limit": "5"}))
    assert [e["id"] for e in result["entries"]] == ids[::-1][:5]
    assert result["stream_length"] == 30 and result["next_before"] == ids[-5]
    older = review.list_entries(store, K, review.list_query({"limit": "5", "before": result["next_before"]}))
    assert [e["id"] for e in older["entries"]] == ids[::-1][5:10]


def test_filters():
    store = FakeStore()
    ids = many(store)
    store_rejection(store, b"\xe0\x00", stage=STRUCTURAL, detail="bad CCSDS version 7")

    def ids_for(**params):
        return [e["id"] for e in review.list_entries(store, K, review.list_query(params))["entries"]]

    assert ids_for(apid="3", limit="1000") == [i for n, i in enumerate(ids) if n % 2][::-1]
    assert ids_for(apid="0x004") == ids_for(rule_id="deny-4")
    assert ids_for(search="NUMBER 7") == [ids[7]]
    assert ids_for(stage="structural") == []                 # not in the framed stream
    assert len(ids_for(stage="STRUCTURAL", stream="raw")) == 1


def test_the_whole_stream_is_searched_and_the_end_is_reported():
    store = FakeStore()
    ids = many(store, 1200)  # more than one scan batch
    result = review.list_entries(store, K, review.list_query({"search": "no such text", "limit": "10"}))
    assert result["entries"] == [] and result["scanned"] == 1200 and result["next_before"] is None
    found = review.list_entries(store, K, review.list_query({"search": "number 0", "limit": "10"}))
    assert [e["id"] for e in found["entries"]] == [ids[0]]


@pytest.mark.parametrize("params, message", [
    ({"limit": "0"}, "limit must be 1 to 1000"),
    ({"limit": "5000"}, "limit must be 1 to 1000"),
    ({"limit": "ten"}, "whole number"),
    ({"stream": "audit"}, "stream must be one of"),
    ({"stage": "ALLOW"}, "stage must be one of"),
    ({"apid": "0x800"}, "apid must be 0 to 0x7FF"),
    ({"apid": "x"}, "apid must be a number"),
    ({"review": "deleted"}, "review must be one of"),
    ({"search": "a\u202eb"}, "invisible"),
    ({"before": "+"}, "before must be"),
])
def test_bad_filters_are_refused(params, message):
    with pytest.raises(review.QueryError, match=message):
        review.list_query(params)


# ---- review states ----------------------------------------------------------------

def test_review_states_are_stored_audited_and_filterable():
    store = FakeStore()
    ids = many(store, 4)
    body = {"interface": IFACE, "stream": "quarantine", "ids": ids[:2] + ["1-0"], "state": "false_positive",
            "note": "rule deny-4 too strict", "requested_by": "alice"}
    stream, checked_ids, state, note, requested_by = review.review_body(body)
    result = review.set_review(store, K, IFACE, stream, checked_ids, state, note, "alice@ops", requested_by)
    assert result["updated"] == ids[:2] and result["missing"] == ["1-0"]
    entry = review.get_entry(store, K, "quarantine", ids[0])
    assert entry["review_state"] == "false_positive"
    assert (entry["review"]["note"], entry["review"]["user"]) == ("rule deny-4 too strict", "alice@ops")
    listed = review.list_entries(store, K, review.list_query({"review": "false_positive"}))["entries"]
    assert sorted(e["id"] for e in listed) == sorted(ids[:2])
    assert len(review.list_entries(store, K, review.list_query({"review": "new"}))["entries"]) == 2
    [(_, audit)] = store.streams[K["audit"]]
    assert audit[b"action"] == b"REVIEW" and audit[b"state"] == b"false_positive" and audit[b"count"] == b"2"

    review.set_review(store, K, IFACE, "quarantine", ids[:1], "new", "", "alice@ops", "")
    assert review.get_entry(store, K, "quarantine", ids[0])["review_state"] == "new"


def test_a_released_entry_shows_released():
    store = FakeStore()
    [entry_id] = many(store, 1)
    store.hset(K["released"], entry_id, json.dumps({"time": "t", "requested_by": "bob", "reason": "ok"}))
    view = review.get_entry(store, K, "quarantine", entry_id)
    assert view["review_state"] == "released" and view["released"]["requested_by"] == "bob"
    assert [e["id"] for e in review.list_entries(store, K, review.list_query({"review": "released"}))["entries"]] \
        == [entry_id]


def test_reviews_of_raw_and_framed_entries_do_not_collide():
    store = FakeStore()
    store.clock = itertools.chain([5, 5], itertools.count(6))  # the same id in both streams
    framed = store_rejection(store, status_3())
    raw = store_rejection(store, b"\xe0\x00", stage=STRUCTURAL)
    assert framed == raw
    review.set_review(store, K, IFACE, "raw", [raw], "threat", "", "", "")
    assert review.get_entry(store, K, "quarantine", framed)["review_state"] == "new"
    assert review.get_entry(store, K, "raw", raw)["review_state"] == "threat"


@pytest.mark.parametrize("change, message", [
    ({"state": "released"}, "releasing is a separate action"),
    ({"ids": []}, "non-empty list"),
    ({"ids": ["1-0"] * 201}, "at most 200"),
    ({"ids": ["1-0", "*"]}, "id must be"),
    ({"note": "x" * 257}, "longer than 256"),
    ({"note": "a\nb"}, "control or invisible"),
    ({"extra": 1}, "unknown field"),
])
def test_bad_reviews_are_refused(change, message):
    body = {"interface": IFACE, "stream": "quarantine", "ids": ["1-0"], "state": "reviewed", **change}
    with pytest.raises(review.QueryError, match=message):
        review.review_body(body)


def test_reviews_of_trimmed_entries_are_pruned(monkeypatch):
    monkeypatch.setattr(review, "REVIEW_KEEP", 3)
    store = FakeStore()
    ids = many(store, 6)
    review.set_review(store, K, IFACE, "quarantine", ids, "reviewed", "", "", "")
    del store.streams[K["quarantine"]][:4]  # the capped stream dropped the oldest four
    review.set_review(store, K, IFACE, "quarantine", ids[4:], "threat", "", "", "")
    assert sorted(store.hkeys(K["review"])) == sorted(f"quarantine:{i}".encode() for i in ids[4:])


# ---- the HTTP service and the admin check ------------------------------------------

class Response:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def opener_for(status, calls=None):
    def opener(request, timeout):
        if calls is not None:
            calls.append((request.full_url, request.headers.get("Authorization")))
        if status == 200:
            return Response(200)
        if status is None:
            raise urllib.error.URLError("connection refused")
        raise urllib.error.HTTPError(request.full_url, status, "no", {}, None)
    return opener


def app(status=200, store=None, calls=None):
    check = service.AdminCheck("http://cosmos:2901", opener=opener_for(status, calls))
    fake = store or FakeStore()
    return service.ReviewApp(admin_check=check, store=lambda: fake), fake


AUTH = {"Authorization": "token-of-alice"}


def test_list_through_http_asks_cosmos_with_the_callers_token():
    calls = []
    web, store = app(calls=calls)
    many(store, 3)
    status, payload = web.handle("GET", f"/eaglegate-quarantine/entries?scope={SCOPE}&interface={IFACE}&limit=2", AUTH)
    assert status == 200 and len(payload["entries"]) == 2 and payload["interface"] == IFACE
    assert calls == [("http://cosmos:2901/openc3-api/secrets?scope=DEFAULT", "token-of-alice")]
    web.handle("GET", f"/eaglegate-quarantine/entries?scope={SCOPE}&interface={IFACE}", AUTH)
    assert len(calls) == 1  # cached for a while


@pytest.mark.parametrize("cosmos_status, status", [(401, 401), (403, 403), (500, 502), (None, 502)])
def test_only_admins_get_anything(cosmos_status, status):
    web, store = app(cosmos_status)
    many(store, 3)
    got, payload = web.handle("GET", f"/eaglegate-quarantine/entries?scope={SCOPE}&interface={IFACE}", AUTH)
    assert got == status and set(payload) == {"error"}
    got, _ = web.handle("GET", f"/eaglegate-quarantine/entries?scope={SCOPE}&interface={IFACE}", {})
    assert got == 401


def test_a_refusal_is_not_cached():
    web, _ = app(403)
    assert web.handle("GET", f"/eaglegate-quarantine/entries?scope={SCOPE}&interface={IFACE}", AUTH)[0] == 403
    web.admin_check.opener = opener_for(200)
    assert web.handle("GET", f"/eaglegate-quarantine/entries?scope={SCOPE}&interface={IFACE}", AUTH)[0] == 200


def test_entry_and_review_through_http():
    web, store = app()
    [entry_id] = many(store, 1)
    status, payload = web.handle("GET", f"/eaglegate-quarantine/entry?scope={SCOPE}&interface={IFACE}"
                                        f"&stream=quarantine&id={entry_id}", AUTH)
    assert status == 200 and payload["entry"]["id"] == entry_id
    status, _ = web.handle("GET", f"/eaglegate-quarantine/entry?scope={SCOPE}&interface={IFACE}&id=9-9", AUTH)
    assert status == 404
    body = json.dumps({"interface": IFACE, "stream": "quarantine", "ids": [entry_id], "state": "reviewed"}).encode()
    headers = {**AUTH, "Content-Type": "application/json"}
    status, payload = web.handle("POST", f"/eaglegate-quarantine/review?scope={SCOPE}", headers, body)
    assert status == 200 and payload["updated"] == [entry_id]
    assert web.handle("POST", f"/eaglegate-quarantine/review?scope={SCOPE}", AUTH, body)[0] == 415
    assert web.handle("POST", f"/eaglegate-quarantine/review?scope={SCOPE}", headers, b"{")[0] == 400


@pytest.mark.parametrize("method, path, status", [
    ("GET", "/eaglegate-quarantine/health", 200),
    ("GET", "/eaglegate-quarantine/nothing", 404),
    ("POST", "/eaglegate-quarantine/entries?scope=DEFAULT", 405),
    ("GET", "/elsewhere", 404),
    ("GET", "/eaglegate-quarantine/entries?scope=DEF%2FAULT&interface=X", 400),
    ("GET", "/eaglegate-quarantine/entries?scope=DEFAULT&interface=X__Y%0A", 400),  # $ would allow the newline
    ("GET", "/eaglegate-quarantine/entry?scope=DEFAULT&interface=X&id=1-0%0A", 400),
])
def test_routing(method, path, status):
    web, _ = app()
    assert web.handle(method, path, AUTH)[0] == status


def test_health_needs_no_login_and_says_nothing_else():
    web, _ = app(401)
    assert web.handle("GET", "/eaglegate-quarantine/health", {}) == (200, {"ok": True})


def test_unexpected_errors_do_not_leak_details():
    class Broken(FakeStore):
        def xrevrange(self, *args, **kwargs):
            raise RuntimeError("secret internals")

    web, _ = app(store=Broken())
    status, payload = web.handle("GET", f"/eaglegate-quarantine/entries?scope={SCOPE}&interface={IFACE}", AUTH)
    assert status == 500 and "secret internals" not in payload["error"]


def test_user_name_comes_from_an_enterprise_token_only():
    claims = base64.urlsafe_b64encode(json.dumps({"preferred_username": "alice\u202e"}).encode()).rstrip(b"=")
    assert service.user_from_token(f"Bearer x.{claims.decode()}.sig") == "alice\\u202e"
    assert service.user_from_token("plain-core-token") == ""
    assert service.user_from_token("a.!!!.c") == ""
