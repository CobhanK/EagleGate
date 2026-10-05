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
        self.script_view = script_view  # what get_target_file returns, if different
        self.pending = []
        self.output = []
        self.reload_requests = 0

    def namespace(self):
        ns = {}

        def get_target_file(path):
            text = self.script_view if self.script_view is not None else self.store.text
            return io.BytesIO(text.encode() if isinstance(text, str) else text)

        def interface_protocol_cmd(name, cmd, *args, read_write="READ_WRITE"):
            assert name == "EAGLEGATE_INT"
            self.reload_requests += 1
            self.pending.append(lambda: self.iface.protocol_cmd(cmd, *args, read_write=read_write))

        def interface_details(name):
            assert name == "EAGLEGATE_INT"
            return json.loads(json.dumps(self.iface.details(), cls=JsonEncoder), cls=JsonDecoder)

        def wait(seconds):
            while self.pending:
                self.pending.pop(0)()

        ns.update(get_target_file=get_target_file,
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


def test_reports_when_interface_rejects_the_reload():
    """The file is edited again between the procedure reading it and the
    interface loading it. The procedure must report the error, not claim success."""
    iface, proto, store = build()
    cosmos = FakeCosmos(iface, store, script_view=V2)
    store.text = "{broken"
    with pytest.raises(RuntimeError, match="Interface rejected the rules"):
        cosmos.run_procedure()
    assert proto.ruleset.version == 1


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
