"""Admin requests (eaglegate_admin_requests.py) and RESTORE_TRUST: an operator's
protocol command alone must never be enough to act."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from conftest import hk_status, rules_json, status_3
from eaglegate_admin_requests import MAX_AGE, NonceLog, RequestError, parse_request
from eaglegate_firewall_protocol import EaglegateFirewallProtocol
from eaglegate_test_support import FakeRulesStore, ScriptedInterface, admin_request

PLUGIN_ARGS = ["1024", "EAGLEGATE/rules/firewall_rules.json"]
NOW = datetime(2026, 11, 9, 18, 0, 0, tzinfo=timezone.utc)


def at(seconds_from_now):
    return (NOW + timedelta(seconds=seconds_from_now)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- parse_request ----

def test_valid_request_parses():
    text, sha = admin_request(reason="  rebooted  ", requested_at=at(-5), params={"spi": 7})
    request = parse_request(text, "restore_trust", sha, now=NOW)
    assert (request.kind, request.reason, request.requested_by, request.params) == \
        ("restore_trust", "rebooted", "alice", {"spi": 7})
    assert request.sha256 == sha
    assert request.audit_fields()["request_sha256"] == sha


def test_sha256_is_compared_case_insensitively():
    text, sha = admin_request(requested_at=at(0))
    assert parse_request(text, "restore_trust", sha.upper(), now=NOW).sha256 == sha


@pytest.mark.parametrize("change, message", [
    ({"kind": "reset_replay"}, "is for 'reset_replay'"),
    ({"reason": ""}, "reason is required"),
    ({"reason": "   "}, "reason is required"),
    ({"reason": "x" * 257}, "longer than 256"),
    ({"reason": "line\nforged log line"}, "control or invisible"),
    ({"reason": "abc\u202edef"}, "control or invisible"),
    ({"nonce": "short"}, "nonce must be"),
    ({"nonce": "has spaces in it ok"}, "nonce must be"),
    ({"requested_by": 7}, "requested_by"),
    ({"requested_by": "x" * 65}, "requested_by"),
    ({"params": []}, "params must be an object"),
    ({"requested_at": "yesterday"}, "not a valid time"),
    ({"requested_at": "2026-11-09T18:00:00"}, "time zone"),
    ({"requested_at": at(-MAX_AGE - 1)}, "expired"),
    ({"requested_at": at(120)}, "in the future"),
    ({"surprise": 1}, "unknown request key"),
])
def test_bad_requests_are_refused(change, message):
    defaults = {"requested_at": at(0)}
    text, sha = admin_request(**{**defaults, **change})
    with pytest.raises(RequestError, match=message):
        parse_request(text, "restore_trust", sha, now=NOW)


def test_request_must_match_the_commanded_sha256():
    text, sha = admin_request(requested_at=at(0))
    with pytest.raises(RequestError, match="does not match"):
        parse_request(text, "restore_trust", "0" * 64, now=NOW)
    with pytest.raises(RequestError, match="does not match"):
        parse_request(text, "restore_trust", None, now=NOW)


def test_missing_oversized_and_non_json_requests():
    with pytest.raises(RequestError, match="no restore_trust request"):
        parse_request(None, "restore_trust", "x", now=NOW)
    big = "x" * 9000
    with pytest.raises(RequestError, match="more than"):
        parse_request(big, "restore_trust", "x", now=NOW)
    import hashlib

    for text in ("{broken", "[1]"):
        with pytest.raises(RequestError, match="not valid JSON|must be a JSON object"):
            parse_request(text, "restore_trust", hashlib.sha256(text.encode()).hexdigest(), now=NOW)


def test_small_clock_skew_is_accepted():
    text, sha = admin_request(requested_at=at(30))
    assert parse_request(text, "restore_trust", sha, now=NOW)


def test_nonce_log_refuses_reuse_and_stays_bounded():
    log = NonceLog(size=3)
    for nonce in "abcd":
        log.use(nonce)
    with pytest.raises(RequestError, match="already used"):
        log.use("d")
    assert len(log.seen) == 3 and "a" not in log.seen


# ---- RESTORE_TRUST on a live interface ----

def untrusted_interface(chunks):
    """A connection whose first packet (APID 3) was rejected, then more data."""
    store = FakeRulesStore(rules_json([{"id": "allow-hk", "action": "ALLOW", "match": {"apid": [2]}}]))
    iface = ScriptedInterface([status_3()] + chunks)
    fw = iface.add_protocol(EaglegateFirewallProtocol, PLUGIN_ARGS, "READ")
    fw.store = lambda: store
    iface.connect()
    assert iface.read() is None  # the first packet is rejected; the rest is discarded
    assert fw.connection_untrusted
    return iface, fw, store


def upload(store, **kwargs):
    text, sha = admin_request(**kwargs)
    store.requests["restore_trust"] = text
    return sha


def test_restore_trust_resumes_the_same_connection(valkey, log):
    iface, fw, store = untrusted_interface([hk_status(), hk_status()])
    assert iface.read() is None  # everything discarded so far
    assert fw.connection_untrusted

    iface.chunks = [hk_status(), status_3(), hk_status()]  # the sender keeps sending
    sha = upload(store, reason="first packet was a stale buffer")
    iface.protocol_cmd("RESTORE_TRUST", sha, read_write="READ")
    assert not fw.connection_untrusted and fw.trust_restores == 1
    packets = []
    while (p := iface.read()) is not None:
        packets.append(p.buffer)
    assert packets == [hk_status(), hk_status()]
    assert not fw.connection_untrusted  # a later rejection affects only its own packet

    assert "restore_trust" not in store.requests  # consumed
    [audit] = valkey.stream("_AUDIT__EAGLEGATE_INT")
    assert (audit["action"], audit["ok"], audit["reason"]) == ("RESTORE_TRUST", "true",
                                                              "first packet was a stale buffer")
    assert audit["request_sha256"] == sha and "its first packet was rejected" in audit["previous_cause"]
    action = iface.details()["read_protocols"][0]["firewall"]["admin_actions"][0]
    assert action["ok"] is True and action["audit_id"]
    assert fw.status_items()["TRUST_RESTORES"] == 1
    assert any(level == "WARN" and "RESTORE_TRUST done" in msg for level, msg in log)


def test_restore_trust_without_an_uploaded_request_is_refused(valkey):
    _, fw, _ = untrusted_interface([])
    assert fw.protocol_cmd("RESTORE_TRUST", "abc") is True  # handled, but refused
    assert fw.connection_untrusted
    action = fw.admin_actions[-1]
    assert action["ok"] is False and "no restore_trust request" in action["detail"]
    [audit] = valkey.stream("_AUDIT__EAGLEGATE_INT")
    assert audit["ok"] == "false"


def test_restore_trust_with_the_wrong_sha256_is_refused():
    _, fw, store = untrusted_interface([])
    upload(store)
    fw.protocol_cmd("RESTORE_TRUST", "0" * 64)
    assert fw.connection_untrusted and "does not match" in fw.admin_actions[-1]["detail"]
    assert "restore_trust" in store.requests  # not consumed


def test_restore_trust_request_works_only_once(valkey):
    _, fw, store = untrusted_interface([])
    text, sha = admin_request()
    store.requests["restore_trust"] = text
    fw.protocol_cmd("RESTORE_TRUST", sha)
    assert not fw.connection_untrusted
    fw.mark_untrusted("test")
    store.requests["restore_trust"] = text  # e.g. the delete failed, or someone put it back
    fw.protocol_cmd("RESTORE_TRUST", sha)
    assert fw.connection_untrusted and "already used" in fw.admin_actions[-1]["detail"]


def test_failed_delete_is_logged_but_the_nonce_still_protects(log):
    _, fw, store = untrusted_interface([])
    store.fail_delete = True
    sha = upload(store)
    fw.protocol_cmd("RESTORE_TRUST", sha)
    assert not fw.connection_untrusted
    assert any(level == "WARN" and "could not delete the used restore_trust request" in msg for level, msg in log)


def test_restore_trust_on_a_trusted_connection_changes_nothing():
    store = FakeRulesStore(rules_json([]))
    iface = ScriptedInterface([])
    fw = iface.add_protocol(EaglegateFirewallProtocol, PLUGIN_ARGS, "READ")
    fw.store = lambda: store
    iface.connect()
    fw.protocol_cmd("RESTORE_TRUST", upload(store))
    action = fw.admin_actions[-1]
    assert action["ok"] is True and "nothing changed" in action["detail"] and fw.trust_restores == 0


def test_unreadable_request_is_refused_not_raised():
    _, fw, store = untrusted_interface([])

    def broken(kind):
        raise ConnectionError("bucket down")

    store.read_request = broken
    fw.protocol_cmd("RESTORE_TRUST", "abc")
    assert "could not read the restore_trust request" in fw.admin_actions[-1]["detail"]


def test_audit_failure_does_not_block_the_action(valkey):
    _, fw, store = untrusted_interface([])
    valkey.fail = True
    fw.protocol_cmd("RESTORE_TRUST", upload(store))
    assert not fw.connection_untrusted
    assert fw.admin_actions[-1]["audit_id"] is None


def test_details_show_why_the_connection_is_untrusted():
    iface, fw, _ = untrusted_interface([])
    iface.read()
    details = json.loads(json.dumps(iface.details(), default=str))["read_protocols"][0]["firewall"]
    assert details["connection_untrusted"] is True
    assert details["untrusted_since"]
    assert details["untrusted_cause"].startswith("its first packet was rejected: DENY by default action")


def test_the_pages_request_format_is_accepted():
    """tests/fixtures/admin_request_example.json is built by the page's
    adminRequest.js (its test checks that); the firewall must accept it."""
    import hashlib
    import os

    from conftest import ROOT

    with open(os.path.join(ROOT, "tests", "fixtures", "admin_request_example.json")) as f:
        example = json.load(f)
    text = example["text"]
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    request = parse_request(text, example["inputs"]["kind"], sha, now=datetime(2026, 11, 9, 18, 0, 5,
                                                                              tzinfo=timezone.utc))
    assert (request.reason, request.requested_by, request.params) == \
        (example["inputs"]["reason"], "alice", {"spi": 7})
