import json
import os
import sys

# Running without Docker: tell COSMOS's own Logger not to publish to Valkey.
# Must be set before anything imports openc3.
os.environ.setdefault("OPENC3_NO_STORE", "1")

import pytest  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
LIB = os.path.join(ROOT, "targets", "EAGLEGATE", "lib")
RULES_PATH = os.path.join(ROOT, "targets", "EAGLEGATE", "rules", "firewall_rules.json")
PLUGIN_TXT = os.path.join(ROOT, "plugin.txt")
PROCEDURE_PATH = os.path.join(ROOT, "targets", "EAGLEGATE", "procedures", "apply_firewall_rules.py")

# Make the target's lib/ importable, the same way COSMOS does at runtime
sys.path.insert(0, LIB)

import eaglegate_firewall_protocol  # noqa: E402
import eaglegate_quarantine  # noqa: E402

# The real COSMOS boundary methods, before the `valkey` fixture replaces them
REAL_WRITE = eaglegate_quarantine.QuarantineWriter._write
REAL_INJECT = eaglegate_quarantine.StatusPublisher._inject


class FakeValkey:
    """Records what the quarantine writer and status publisher would send to COSMOS."""

    def __init__(self):
        self.entries = []   # (stream, fields, maxlen)
        self.status = []    # item_hash of each FIREWALL_STATUS packet
        self.fail = False   # make every write raise, like a Valkey outage

    def write(self, writer, stream, fields, maxlen):
        if self.fail:
            raise ConnectionError("valkey down")
        self.entries.append((stream, fields, maxlen))
        return f"{len(self.entries)}-0".encode()

    def inject(self, publisher, message_json):
        if self.fail:
            raise ConnectionError("valkey down")
        message = json.loads(message_json)
        assert (message["target_name"], message["packet_name"]) == ("EAGLEGATE", "FIREWALL_STATUS")
        self.status.append(message["item_hash"])

    def stream(self, suffix):
        """Field dicts written to the stream whose name ends with suffix."""
        return [fields for stream, fields, _ in self.entries if stream.endswith(suffix)]


@pytest.fixture(autouse=True)
def valkey(monkeypatch):
    """No test ever talks to a real Valkey."""
    fake = FakeValkey()
    monkeypatch.setattr(eaglegate_quarantine.QuarantineWriter, "_write",
                        lambda self, stream, fields, maxlen: fake.write(self, stream, fields, maxlen))
    monkeypatch.setattr(eaglegate_quarantine.StatusPublisher, "_inject",
                        lambda self, message_json: fake.inject(self, message_json))
    return fake


def decide(ruleset, packet, now=None):
    """(action, rule_id) of a Verdict, for compact assertions."""
    verdict = ruleset.evaluate(packet, now=now)
    return (verdict.action, verdict.rule_id)


@pytest.fixture(autouse=True)
def log(monkeypatch):
    """Capture firewall log calls instead of using COSMOS logging infrastructure."""
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
    return messages


def ccsds(apid, payload=b"\x00", packet_type=0, sec_hdr=0, version=0, seq=0, length_field=None):
    """Build a CCSDS Space Packet. length_field overrides the computed value (for attacks)."""
    if length_field is None:
        length_field = len(payload) - 1
    word1 = (version << 13) | (packet_type << 12) | (sec_hdr << 11) | apid
    word2 = (0b11 << 14) | seq
    return (word1.to_bytes(2, "big") + word2.to_bytes(2, "big")
            + length_field.to_bytes(2, "big") + payload)


# Packets the shipped rules allow: exact sizes as defined in cmd_tlm/tlm.txt
HK_STATUS_LENGTH = 11  # APID 2
STATUS_3_LENGTH = 10   # APID 3


def hk_status(**kwargs):
    return ccsds(2, bytes(HK_STATUS_LENGTH - 6), **kwargs)


def status_3(**kwargs):
    return ccsds(3, bytes(STATUS_3_LENGTH - 6), **kwargs)


def rules_json(rules, default_action="DENY", version=1, **extra):
    return json.dumps({"version": version, "default_action": default_action, "rules": rules, **extra})


def shipped_rules_text():
    with open(RULES_PATH, "rb") as f:
        return f.read()
