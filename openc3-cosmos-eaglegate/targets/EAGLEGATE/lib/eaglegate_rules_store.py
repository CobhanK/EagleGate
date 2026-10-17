"""Where the firewall rules live in COSMOS storage, and who may write them.

The rules are kept in the COSMOS config bucket OUTSIDE targets_modified:

  {scope}/eaglegate/{TARGET}/rules_pending.json   written by an admin (the
                                                  EagleGate tool page or the
                                                  apply_firewall_rules procedure)
  {scope}/eaglegate/{TARGET}/rules_active.json    written ONLY by the firewall,
                                                  after the pending file validated
  {scope}/eaglegate/{TARGET}/history/...          a copy of every version that
                                                  became active, for rollback

Why there: the COSMOS storage API lets any user with system_set write
targets_modified, but every other config bucket path needs the admin role
(Enterprise) or a valid login (Core). Reading the rules only from these keys
means the COSMOS server, not this plugin, enforces who can change the firewall.

The plugin's original rules/firewall_rules.json is the fallback until a rule
set has been applied. The pending file is never loaded at startup, so an
invalid upload cannot leave the firewall denying everything after a restart.
"""
from eaglegate_quarantine import _Guarded

HISTORY_KEEP = 50  # newest active versions kept in history/


def rules_keys(scope, target_name):
    base = f"{scope}/eaglegate/{target_name}"
    return {
        "pending": f"{base}/rules_pending.json",
        "active": f"{base}/rules_active.json",
        "history": f"{base}/history/",
    }


def history_name(version, sha256):
    """Zero padded so the bucket listing sorts by version."""
    return f"{version:06d}-{sha256[:12]}.json"


class RulesStore(_Guarded):
    """Reads and writes the rule keys. Reads return None when a key is missing;
    write failures are counted rather than raised, so they can never change a
    firewall decision."""

    def __init__(self, scope, target_name, original_path):
        super().__init__()
        self.scope = scope
        self.keys = rules_keys(scope, target_name)
        self.original_path = original_path  # e.g. EAGLEGATE/rules/firewall_rules.json

    def read_pending(self):
        return self._get(self.keys["pending"])

    def read_active(self):
        return self._get(self.keys["active"])

    def read_original(self):
        return self._get(f"{self.scope}/targets/{self.original_path}")

    def save_active(self, text, version, sha256):
        """Make text the startup rule set and keep a copy in history.
        Returns True when the active copy was written."""
        try:
            self._put(self.keys["active"], text)
        except Exception as error:
            self._failed(error)
            return False
        try:
            self._put(self.keys["history"] + history_name(version, sha256), text)
            self._prune_history()
        except Exception as error:
            self._failed(error)  # active is saved; a missing history copy is not fatal
        return True

    def _prune_history(self):
        names = sorted(self._list(self.keys["history"]))
        for name in names[:-HISTORY_KEEP]:
            self._delete(self.keys["history"] + name)

    # ---- COSMOS boundary: separate methods so tests need no bucket ----------

    def _bucket(self):
        from openc3.environment import OPENC3_CONFIG_BUCKET
        from openc3.utilities.bucket import Bucket

        return Bucket.get_client(), OPENC3_CONFIG_BUCKET

    def _get(self, key):
        client, bucket = self._bucket()
        response = client.get_object(bucket=bucket, key=key)
        if not response or not response.get("Body"):
            return None
        return response["Body"].read()

    def _put(self, key, text):
        client, bucket = self._bucket()
        body = text.encode("utf-8") if isinstance(text, str) else text
        client.put_object(bucket=bucket, key=key, body=body, content_type="application/json")

    def _list(self, prefix):
        client, bucket = self._bucket()
        return [item["Key"][len(prefix):] for item in client.list_objects(bucket=bucket, prefix=prefix)]

    def _delete(self, key):
        client, bucket = self._bucket()
        client.delete_object(bucket=bucket, key=key)
