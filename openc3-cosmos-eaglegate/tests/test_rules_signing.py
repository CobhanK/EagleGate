"""Signed rules_active.json: the firewall only runs rules it activated itself."""
import json

import pytest

from conftest import hk_status, rules_json, shipped_rules_text
from eaglegate_rules_signing import KEY_ENV, RulesSigner
from test_firewall_protocol import PLUGIN_ARGS, ScriptedInterface, apids, build, read_all
from eaglegate_firewall_protocol import EaglegateFirewallProtocol

KEY = "11" * 32
OTHER_KEY = "22" * 32
V2 = rules_json([{"id": "allow-all", "action": "ALLOW", "match": {}}], version=2)
V3 = rules_json([{"id": "allow-all-v3", "action": "ALLOW", "match": {}}], version=3)


@pytest.fixture
def signing(monkeypatch):
    monkeypatch.setenv(KEY_ENV, KEY)


def restart(store, chunks=()):
    """A new interface process reading the same bucket (container restart)."""
    iface = ScriptedInterface(chunks)
    proto = iface.add_protocol(EaglegateFirewallProtocol, PLUGIN_ARGS, "READ")
    proto.store = lambda: store
    iface.connect()
    return iface, proto


def signed_store():
    """A store whose active file is V2, applied (and signed) by the firewall."""
    iface, proto, store = build()
    store.pending = V2
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    assert proto.rules_signed and store.active_signature
    return store


def firewall(iface):
    return iface.details()["read_protocols"][0]["firewall"]


def test_signing_off_by_default():
    iface, proto, store = build()
    store.pending = V2
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    assert store.active_signature is None
    assert firewall(iface)["rules_signing"] == {"enabled": False, "key_env": KEY_ENV, "error": None,
                                                "running_signed": False}


def test_signed_active_survives_restart(signing):
    store = signed_store()
    iface, proto = restart(store, [hk_status()])
    assert proto.ruleset.version == 2 and proto.rules_source == "active" and proto.rules_signed
    assert firewall(iface)["rules_signing"]["running_signed"] is True


def test_file_changed_in_bucket_is_refused_at_startup(signing):
    store = signed_store()
    store.active = V2.replace('"ALLOW"', '"DENY"')  # edited with the bucket's own credentials
    iface, proto = restart(store, [hk_status()])
    assert proto.ruleset.version == -1 and read_all(iface) == []  # fail closed
    assert "failed its signature check" in proto.rules_error


def test_file_changed_while_running_keeps_last_known_good(signing):
    iface, proto, store = build()
    store.pending = V2
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    store.active = V3  # tampered, with the old signature
    iface.chunks = [hk_status()]
    iface.connect()
    assert proto.ruleset.version == 2 and "signature check" in proto.rules_error
    assert apids(read_all(iface)) == [2]


def test_signature_cannot_be_moved_to_another_file(signing):
    """The MAC covers the bucket key, so a signature made for one key fails on another."""
    store = signed_store()
    store.active_signature = RulesSigner().sign(store.keys["pending"], store.active)
    _, proto = restart(store)
    assert proto.ruleset.version == -1


def test_wrong_key_is_refused(signing, monkeypatch):
    store = signed_store()
    monkeypatch.setenv(KEY_ENV, OTHER_KEY)
    _, proto = restart(store)
    assert proto.ruleset.version == -1 and "different key" in proto.rules_error


def test_missing_signature_or_file_never_falls_back_to_unsigned_rules(signing):
    store = signed_store()
    store.active_signature = None
    _, proto = restart(store)
    assert proto.ruleset.version == -1
    store.active = None  # deleted: the plugin original must NOT be used instead
    _, proto = restart(store)
    assert proto.ruleset.version == -1 and "no signed" in proto.rules_error


def test_first_apply_bootstraps_signing(signing):
    """Turning signing on: deny-all until an admin applies the rules once."""
    iface, proto, store = build()
    assert proto.ruleset.version == -1 and "no signed" in proto.rules_error
    store.pending = shipped_rules_text()
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    assert proto.ruleset.version == 1 and proto.rules_signed
    _, restarted = restart(store)
    assert restarted.ruleset.version == 1


def test_reapplying_repairs_a_tampered_file(signing):
    store = signed_store()
    store.active = V3  # tampered
    iface, proto = restart(store)
    assert proto.ruleset.version == -1
    store.pending = V2
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    assert proto.ruleset.version == 2
    assert restart(store)[1].ruleset.version == 2


def test_older_signed_copy_is_refused_while_running(signing):
    iface, proto, store = build()
    store.pending = V2
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    old = (store.active, store.active_signature)  # an attacker keeps a copy of v2
    store.pending = V3
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    store.active, store.active_signature = old  # and puts it back
    iface.connect()
    assert proto.ruleset.version == 3 and "rollback" in proto.rules_error


def test_restoring_an_older_version_through_apply_is_allowed(signing):
    """Rollback protection only applies to files changed behind the firewall's back."""
    iface, proto, store = build()
    store.pending = V3
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    store.pending = V2
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    assert proto.ruleset.version == 2
    iface.connect()
    assert proto.ruleset.version == 2 and proto.rules_error is None


@pytest.mark.parametrize("bad_key, reason", [("not hex", "as hex"), ("11" * 16, "at least 32 bytes")])
def test_misconfigured_key_loads_nothing_and_refuses_apply(monkeypatch, bad_key, reason):
    monkeypatch.setenv(KEY_ENV, bad_key)
    iface, proto, store = build()
    assert proto.ruleset.version == -1 and reason in proto.rules_error
    store.pending = V2
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    assert proto.ruleset.version == -1 and "cannot apply" in proto.rules_error
    assert store.active is None
    assert firewall(iface)["rules_signing"]["error"]


def test_key_never_appears_in_details_or_logs(signing, log):
    iface, _, store = build()
    store.pending = V2
    iface.protocol_cmd("RELOAD_RULES", read_write="READ")
    text = json.dumps(firewall(iface), default=str) + json.dumps(log)
    assert KEY not in text and KEY.upper() not in text
