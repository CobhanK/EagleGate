import json
import os
import sys

# Running without Docker: tell COSMOS's own Logger not to publish to Valkey.
# Must be set before anything imports openc3.
os.environ.setdefault("OPENC3_NO_STORE", "1")

import pytest  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
LIB = os.path.join(ROOT, "targets", "EAGLEGATE_SDLS", "lib")
RULES_PATH = os.path.join(ROOT, "targets", "EAGLEGATE_SDLS", "rules", "firewall_rules.json")
PLUGIN_TXT = os.path.join(ROOT, "plugin.txt")
TLM_TXT = os.path.join(ROOT, "targets", "EAGLEGATE_SDLS", "cmd_tlm", "tlm.txt")
# The core plugin (openc3-cosmos-eaglegate), a sibling folder in this repository.
# In COSMOS its target lib/ is on the path because plugin.txt maps the core target.
CORE = os.environ.get("EAGLEGATE_CORE_DIR", os.path.join(ROOT, "..", "openc3-cosmos-eaglegate"))
CORE_LIB = os.path.join(CORE, "targets", "EAGLEGATE", "lib")
CORE_TESTS = os.path.join(CORE, "tests")

for path in (CORE_TESTS, CORE_LIB, LIB):  # LIB ends up first
    sys.path.insert(0, path)

import eaglegate_firewall_protocol  # noqa: E402
import eaglegate_quarantine  # noqa: E402
import eaglegate_sdls_frame_protocol  # noqa: E402
import eaglegate_sdls_replay  # noqa: E402
import eaglegate_sdls_status  # noqa: E402


class FakeValkey:
    """Records what would go to COSMOS: quarantine and audit stream entries,
    FIREWALL_STATUS and LINK_STATUS packets, and the anti-replay hash."""

    def __init__(self):
        self.entries = []    # (stream, fields, maxlen)
        self.status = []     # FIREWALL_STATUS item hashes
        self.link_status = []
        self.hashes = {}     # key -> {field: value}
        self.fail = False

    def _check(self):
        if self.fail:
            raise ConnectionError("valkey down")

    def write(self, stream, fields, maxlen):
        self._check()
        self.entries.append((stream, fields, maxlen))
        return f"{len(self.entries)}-0".encode()

    def inject(self, message_json):
        self._check()
        message = json.loads(message_json)
        if message["packet_name"] == "FIREWALL_STATUS":
            self.status.append(message["item_hash"])
        else:
            self.link_status.append(message["item_hash"])

    def stream(self, suffix):
        return [fields for stream, fields, _ in self.entries if stream.endswith(suffix)]


@pytest.fixture(autouse=True)
def valkey(monkeypatch):
    fake = FakeValkey()
    monkeypatch.setattr(eaglegate_quarantine.QuarantineWriter, "_write",
                        lambda self, stream, fields, maxlen: fake.write(stream, fields, maxlen))
    monkeypatch.setattr(eaglegate_quarantine.StatusPublisher, "_inject", lambda self, m: fake.inject(m))
    monkeypatch.setattr(eaglegate_sdls_status.LinkStatusPublisher, "_inject", lambda self, m: fake.inject(m))

    def hgetall(store):
        fake._check()
        return dict(fake.hashes.get(store.key, {}))

    def hset(store, field_name, value):
        fake._check()
        fake.hashes.setdefault(store.key, {})[field_name] = value

    monkeypatch.setattr(eaglegate_sdls_replay.ReplayStore, "_hgetall", hgetall)
    monkeypatch.setattr(eaglegate_sdls_replay.ReplayStore, "_hset", hset)
    return fake


@pytest.fixture(autouse=True)
def log(monkeypatch):
    """Capture log calls of both protocols."""
    messages = []

    class FakeLogger:
        @staticmethod
        def warn(msg):
            messages.append(("WARN", msg))

        @staticmethod
        def info(msg):
            messages.append(("INFO", msg))

        @staticmethod
        def error(msg):
            messages.append(("ERROR", msg))

    monkeypatch.setattr(eaglegate_firewall_protocol, "Logger", FakeLogger)
    monkeypatch.setattr(eaglegate_sdls_frame_protocol, "Logger", FakeLogger)
    return messages


def shipped_rules():
    with open(RULES_PATH) as f:
        return json.load(f)


def rules_text(**changes):
    """The shipped rules file with top-level keys replaced, and link keys via link_changes."""
    doc = shipped_rules()
    link_changes = changes.pop("link_changes", {})
    doc.update(changes)
    doc["link"] = {**doc["link"], **link_changes}
    return json.dumps(doc)
