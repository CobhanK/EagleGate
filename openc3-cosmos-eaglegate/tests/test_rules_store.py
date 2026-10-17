"""RulesStore against a fake COSMOS bucket client (no Docker)."""
import io
import json

import pytest

from conftest import RULES_PATH
from eaglegate_rules_store import HISTORY_KEEP, RulesStore, history_name, rules_keys
from eaglegate_firewall_protocol import EaglegateFirewallProtocol


class FakeBucket:
    """The parts of openc3.utilities.bucket.Bucket that RulesStore uses."""

    def __init__(self):
        self.objects = {}
        self.fail = False

    def get_object(self, bucket, key):
        assert bucket == "config"
        if key not in self.objects:
            return None  # what the real client returns for NoSuchKey
        return {"Body": io.BytesIO(self.objects[key])}

    def put_object(self, bucket, key, body, content_type=None):
        if self.fail:
            raise ConnectionError("bucket down")
        self.objects[key] = body

    def list_objects(self, bucket, prefix=None):
        return [{"Key": key} for key in self.objects if key.startswith(prefix)]

    def delete_object(self, bucket, key):
        del self.objects[key]


@pytest.fixture
def bucket(monkeypatch):
    fake = FakeBucket()
    monkeypatch.setattr(RulesStore, "_bucket", lambda self: (fake, "config"))
    return fake


def make_store():
    return RulesStore("DEFAULT", "EAGLEGATE", "EAGLEGATE/rules/firewall_rules.json")


def test_keys_are_outside_targets_modified():
    """targets_modified is writable by non-admins; these keys must not be."""
    keys = rules_keys("DEFAULT", "EAGLEGATE")
    assert keys == {
        "pending": "DEFAULT/eaglegate/EAGLEGATE/rules_pending.json",
        "active": "DEFAULT/eaglegate/EAGLEGATE/rules_active.json",
        "history": "DEFAULT/eaglegate/EAGLEGATE/history/",
    }
    assert not any("targets_modified" in key or key.split("/")[1] == "tmp" for key in keys.values())


def test_missing_keys_read_as_none(bucket):
    store = make_store()
    assert store.read_pending() is None and store.read_active() is None


def test_original_is_the_installed_plugin_file(bucket):
    bucket.objects["DEFAULT/targets/EAGLEGATE/rules/firewall_rules.json"] = b"{}"
    bucket.objects["DEFAULT/targets_modified/EAGLEGATE/rules/firewall_rules.json"] = b"draft"
    assert make_store().read_original() == b"{}"  # never the operator-writable draft


def test_save_active_writes_active_and_history(bucket):
    store = make_store()
    assert store.save_active('{"version": 3}', 3, "ab" * 32)
    assert bucket.objects["DEFAULT/eaglegate/EAGLEGATE/rules_active.json"] == b'{"version": 3}'
    assert bucket.objects["DEFAULT/eaglegate/EAGLEGATE/history/000003-abababababab.json"] == b'{"version": 3}'


def test_history_is_pruned_to_newest(bucket):
    store = make_store()
    for version in range(1, HISTORY_KEEP + 6):
        store.save_active("{}", version, f"{version:064x}")
    names = sorted(key.split("/")[-1] for key in bucket.objects if "/history/" in key)
    assert len(names) == HISTORY_KEEP
    assert names[0] == history_name(6, f"{6:064x}")


def test_failed_save_is_counted_not_raised(bucket):
    store = make_store()
    bucket.fail = True
    assert store.save_active("{}", 1, "0" * 64) is False
    assert store.errors == 1 and "bucket down" in store.last_error


def test_protocol_reads_through_the_real_store(bucket, valkey):
    """End to end through RulesStore: apply a pending file, then restart."""
    with open(RULES_PATH, "rb") as f:
        bucket.objects["DEFAULT/targets/EAGLEGATE/rules/firewall_rules.json"] = f.read()
    proto = EaglegateFirewallProtocol("1024", "EAGLEGATE/rules/firewall_rules.json", "DEFAULT")
    assert proto.load_active() and proto.rules_source == "original"
    v2 = json.dumps({"version": 2, "default_action": "DENY", "rules": []})
    bucket.objects["DEFAULT/eaglegate/EAGLEGATE/rules_pending.json"] = v2.encode()
    assert proto.apply_pending()
    restarted = EaglegateFirewallProtocol("1024", "EAGLEGATE/rules/firewall_rules.json", "DEFAULT")
    assert restarted.load_active() and restarted.ruleset.version == 2 and restarted.rules_source == "active"
