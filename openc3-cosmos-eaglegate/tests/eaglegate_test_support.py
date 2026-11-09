"""Fakes shared by the core tests and by extension plugins' tests (eaglegate-sdls).

They stand in for COSMOS's I/O only: the real openc3 Interface and protocol
classes still run. Extension tests put this folder on sys.path to import them."""
import hashlib
import json
import uuid
from datetime import datetime, timezone

from eaglegate_rules_store import rules_keys
from openc3.interfaces.interface import Interface


class ScriptedInterface(Interface):
    """Stands in for TCP: returns scripted chunks, then asks to disconnect."""

    def __init__(self, chunks=()):
        super().__init__()
        self.chunks = list(chunks)
        self.name = "EAGLEGATE_INT"

    def connected(self):
        return True

    def read_interface(self):
        if not self.chunks:
            return (None, None)
        data = self.chunks.pop(0)
        self.read_interface_base(data, None)
        return (data, None)


class FakeRulesStore:
    """Stands in for eaglegate_rules_store.RulesStore (the COSMOS config bucket).

    original: the plugin's rules/firewall_rules.json
    active:   rules_active.json (only the firewall writes it)
    pending:  rules_pending.json (what an admin uploads); `text` is an alias,
              so a test sets store.text and then sends RELOAD_RULES"""

    def __init__(self, original):
        self.original = original
        self.active = None
        self.active_signature = None  # the HMAC stored as metadata on the active object
        self.pending = None
        self.saved = []           # (version, sha256) of every save_active
        self.fail_save = False    # make save_active fail, like a bucket outage
        self.keys = rules_keys("DEFAULT", "EAGLEGATE")
        self.last_error = None
        self.requests = {}        # kind -> text of requests/{kind}.json (admin requests)
        self.fail_delete = False  # make delete_request fail, like a bucket outage

    @property
    def text(self):
        return self.pending

    @text.setter
    def text(self, value):
        self.pending = value

    def read_original(self):
        return self.original

    def read_active(self):
        return self.active, self.active_signature

    def read_pending(self):
        return self.pending

    def read_request(self, kind):
        return self.requests.get(kind)

    def delete_request(self, kind):
        if self.fail_delete:
            self.last_error = "ConnectionError: bucket down"
            return False
        self.requests.pop(kind, None)
        return True

    def save_active(self, text, version, sha256, signature=None):
        if self.fail_save:
            self.last_error = "ConnectionError: bucket down"
            return False
        self.active = text
        self.active_signature = signature
        self.saved.append((version, sha256))
        return True


def admin_request(kind="restore_trust", reason="spacecraft rebooted", nonce=None, requested_at=None,
                  requested_by="alice", params=None, **overrides):
    """(text, sha256) of an admin request file, as the EagleGate page writes it."""
    doc = {
        "kind": kind,
        "reason": reason,
        "nonce": nonce or str(uuid.uuid4()),
        "requested_at": requested_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "requested_by": requested_by,
        "params": {} if params is None else params,
        **overrides,
    }
    text = json.dumps(doc)
    return text, hashlib.sha256(text.encode("utf-8")).hexdigest()
