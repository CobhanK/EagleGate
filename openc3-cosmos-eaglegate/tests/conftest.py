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
