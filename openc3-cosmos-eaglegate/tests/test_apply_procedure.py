"""End-to-end test of the operator procedure apply_firewall_rules.py.

Runs the REAL procedure file against a REAL protocol instance. Only the COSMOS
script API is faked, and interface details go through the same JSON encoding
COSMOS uses, so non-serializable details would fail here too."""
import io
import json

import pytest

from conftest import PROCEDURE_PATH, rules_json, shipped_rules_text
from test_firewall_protocol import build
from openc3.utilities.json import JsonDecoder, JsonEncoder

V2 = rules_json([{"id": "allow-all", "action": "ALLOW", "match": {}}], version=2)


class FakeCosmos:
    """Fake script API. The reload is queued and only runs on the next wait(),
    like the real fire-and-forget interface_protocol_cmd."""

    def __init__(self, iface, store, script_view=None):
        self.iface, self.store = iface, store
        # The operator's draft in targets_modified (or the plugin original)
        self.draft = store.pending if store.pending is not None else store.original
        self.script_view = script_view  # what get_target_file returns, if different
        self.pending = []
        self.output = []
        self.reload_requests = 0
        self.uploads = []          # (key, text) the procedure uploaded
        self.upload_error = None   # make the upload fail, like a non-admin user
        self.after_upload = None   # runs right after the upload, before the reload

    def namespace(self):
        ns = {}

        def get_target_file(path):
            text = self.script_view if self.script_view is not None else self.draft
            return io.BytesIO(text.encode() if isinstance(text, str) else text)

        def interface_protocol_cmd(name, cmd, *args, read_write="READ_WRITE"):
            assert name == "EAGLEGATE_INT"
            self.reload_requests += 1
            self.pending.append(lambda: self.iface.protocol_cmd(cmd, *args, read_write=read_write))

        def interface_details(name):
            assert name == "EAGLEGATE_INT"
            return json.loads(json.dumps(self.iface.details(), cls=JsonEncoder), cls=JsonDecoder)

        def upload(key, text):
            if self.upload_error:
                raise RuntimeError(self.upload_error)
            self.uploads.append((key, text))
            self.store.pending = text
            if self.after_upload:
                self.after_upload()

        def wait(seconds):
            while self.pending:
                self.pending.pop(0)()

        ns.update(eaglegate_test_upload=upload, get_target_file=get_target_file,
                  interface_protocol_cmd=interface_protocol_cmd,
                  interface_details=interface_details, wait=wait,
                  print=lambda *a: self.output.append(" ".join(map(str, a))))
        return ns

    def run_procedure(self):
        with open(PROCEDURE_PATH) as f:
            exec(compile(f.read(), PROCEDURE_PATH, "exec"), self.namespace())


def test_applies_new_rules_and_confirms():
    iface, proto, store = build()
    store.text = V2
    cosmos = FakeCosmos(iface, store)
    cosmos.run_procedure()
    assert proto.ruleset.version == 2
    assert any("SUCCESS: rules version 2 active" in line for line in cosmos.output)


def test_invalid_file_is_reported_and_running_rules_kept():
    iface, proto, store = build()
    store.text = rules_json([{"id": "x", "action": "ALOW", "match": {}}], version=2)
    cosmos = FakeCosmos(iface, store)
    with pytest.raises(RuntimeError, match="nothing was changed:\n.*action must be one of"):
        cosmos.run_procedure()
    assert proto.ruleset.version == 1


def test_uploads_draft_to_admin_only_pending_key_and_names_both_sha256s():
    iface, proto, store = build()
    before = proto.ruleset.sha256
    store.text = V2
    cosmos = FakeCosmos(iface, store)
    calls = []
    real_cmd = iface.protocol_cmd
    iface.protocol_cmd = lambda cmd, *args, **kw: (calls.append((cmd, args)), real_cmd(cmd, *args, **kw))[1]
    cosmos.run_procedure()
    assert cosmos.uploads == [("DEFAULT/eaglegate/EAGLEGATE/rules_pending.json", V2)]
    assert calls == [("RELOAD_RULES", (before, proto.ruleset.sha256))]
    assert store.active == V2  # saved as the startup rule set


def test_reports_when_another_admin_uploads_before_the_reload():
    """Someone else uploads between this procedure's upload and the interface
    applying it. The interface must refuse, and the procedure must say so."""
    iface, proto, store = build()
    store.text = V2
    cosmos = FakeCosmos(iface, store)
    other = rules_json([{"id": "other", "action": "ALLOW", "match": {}}], version=3)
    cosmos.after_upload = lambda: setattr(store, "pending", other)
    with pytest.raises(RuntimeError, match="(?s)Interface rejected the rules.*pending rules file changed"):
        cosmos.run_procedure()
    assert proto.ruleset.version == 1


def test_upload_refused_explains_admin_requirement():
    iface, proto, store = build()
    store.text = V2
    cosmos = FakeCosmos(iface, store)
    cosmos.upload_error = "Could not upload ...; changing the firewall rules needs the admin role"
    with pytest.raises(RuntimeError, match="admin role"):
        cosmos.run_procedure()
    assert proto.ruleset.version == 1 and cosmos.reload_requests == 0


def test_warns_when_version_not_bumped():
    iface, _, store = build()
    store.text = rules_json([{"id": "allow-all", "action": "ALLOW", "match": {}}], version=1)
    cosmos = FakeCosmos(iface, store)
    cosmos.run_procedure()
    assert any("WARNING" in line and "version" in line for line in cosmos.output)


def test_reapplying_unchanged_rules_succeeds_quietly():
    iface, _, store = build()
    cosmos = FakeCosmos(iface, store)
    cosmos.run_procedure()
    assert not any("WARNING" in line for line in cosmos.output)
    assert any("SUCCESS" in line for line in cosmos.output)


def test_warns_when_connection_is_untrusted():
    """Applying fixed rules does not reopen an untrusted connection; say so."""
    iface, proto, store = build()
    proto.connection_untrusted = True
    store.text = V2
    cosmos = FakeCosmos(iface, store)
    cosmos.run_procedure()
    assert any("SUCCESS" in line for line in cosmos.output)
    assert any("WARNING" in line and "Reconnect the interface" in line for line in cosmos.output)
