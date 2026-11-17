"""RELEASE: an admin sends one quarantined packet on into COSMOS.

For a packet the firewall rejected wrongly. Same two steps as RESTORE_TRUST
(eaglegate_admin_requests.py): the EagleGate page uploads
requests/release.json, which only admins can write, then sends

  interface_protocol_cmd("<INTERFACE>", "RELEASE", "<sha256 of that file>")

with params {"entry_id": "<stream entry id>", "sha256": "<sha256 of the
packet bytes>"}. The bytes' sha256 is the one the admin was shown, so a
release can only deliver exactly what was reviewed.

What may be released (decision C6 in EagleGate/DECISIONS.md):
  * only entries of the FRAMED quarantine stream (stages RULE, DEFAULT,
    ERROR): whole packets. Raw entries (STRUCTURAL, UNTRUSTED, LINK) are never
    read here, so they can never be released
  * only whole bytes: a truncated entry is refused
  * only once: the firewall claims the entry in the RELEASED hash with HSETNX
    before delivering it, so two admins (or a replayed command) cannot
    deliver it twice
  * the rules are NOT checked again: a release is an admin override, made
    with a reason and written to the audit stream

The packet is identified against the interface's telemetry targets and
written to the telemetry stream as if the interface had received it now.
Its `extra` carries {"eaglegate_released": "<entry id>"}, so a released
packet can be told apart in COSMOS. A packet COSMOS does not recognise is
refused (released as UNKNOWN it would only be noise).
"""
import hashlib
import re
from datetime import datetime, timezone

ENTRY_ID = re.compile(r"^[0-9]{1,20}-[0-9]{1,20}$")  # a Valkey stream entry id
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RELEASED_EXTRA = "eaglegate_released"


class ReleaseError(Exception):
    """Why a release was refused; shown to the admin."""


def release_params(params):
    """(entry_id, sha256) from the request's params. Raises ReleaseError."""
    params = params or {}
    unknown = sorted(set(params) - {"entry_id", "sha256"})
    if unknown:
        raise ReleaseError(f"unknown release parameter(s) {unknown}")
    entry_id = params.get("entry_id")
    if not isinstance(entry_id, str) or not ENTRY_ID.fullmatch(entry_id):
        raise ReleaseError("entry_id must be a quarantine stream entry id like 1731700000000-0")
    digest = params.get("sha256")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise ReleaseError("sha256 must be the 64 hex digit sha256 of the packet bytes")
    return entry_id, digest


def _flag(fields, name):
    value = fields.get(name, b"")
    return (value.decode("ascii", "replace") if isinstance(value, bytes) else str(value)) == "true"


def _text(fields, name):
    value = fields.get(name, b"")
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def check_entry(fields, entry_id, interface_name, digest):
    """The packet bytes of a stream entry that may be released. Raises ReleaseError."""
    if fields is None:
        raise ReleaseError(f"quarantine entry {entry_id} does not exist (never stored, or already "
                           "trimmed from the capped stream)")
    if _flag(fields, "monitor"):
        raise ReleaseError(f"quarantine entry {entry_id} was recorded in monitor mode: the packet was "
                           "delivered already, so there is nothing to release")
    if not _flag(fields, "releasable"):
        raise ReleaseError(f"quarantine entry {entry_id} is not releasable (stage {_text(fields, 'stage')})")
    if _flag(fields, "truncated"):
        raise ReleaseError(f"quarantine entry {entry_id} holds only part of the packet")
    if _text(fields, "interface") != interface_name:
        raise ReleaseError(f"quarantine entry {entry_id} belongs to {_text(fields, 'interface')}, "
                           f"not {interface_name}")
    data = fields.get("bytes", b"")
    if isinstance(data, str):
        data = data.encode("latin-1")
    actual = hashlib.sha256(data).hexdigest()
    if actual != _text(fields, "sha256"):
        raise ReleaseError(f"quarantine entry {entry_id} is damaged: its bytes do not match its stored sha256")
    if actual != digest:
        raise ReleaseError(f"quarantine entry {entry_id} is not the packet that was reviewed "
                           "(its sha256 differs from the one in the request)")
    if not data:
        raise ReleaseError(f"quarantine entry {entry_id} holds no bytes")
    return bytes(data)


def deliver(interface, data, entry_id, scope):
    """Identify the packet and write it to COSMOS's telemetry stream, as the
    interface microservice does for a received packet. Returns
    (target_name, packet_name). Raises ReleaseError, or whatever COSMOS raises."""
    from openc3.models.target_model import TargetModel
    from openc3.system.system import System
    from openc3.topics.telemetry_topic import TelemetryTopic

    target_names = list(getattr(interface, "tlm_target_names", None) or [])
    if not target_names:
        raise ReleaseError("this interface maps no telemetry targets")
    # identify() only reads the packet definitions; the definition object is
    # shared with the read thread, so the bytes go into a copy of it
    definition = System.telemetry.identify(data, target_names)
    if definition is None:
        raise ReleaseError(f"COSMOS does not recognise this packet as telemetry of {', '.join(target_names)}")
    enabled = getattr(interface, "tlm_target_enabled", None)
    if isinstance(enabled, dict) and enabled and not enabled.get(definition.target_name, False):
        raise ReleaseError(f"telemetry of {definition.target_name} is disabled on this interface")
    packet = definition.clone()
    packet.buffer = bytes(data)
    packet.received_time = datetime.now(timezone.utc)
    packet.stored = False
    packet.extra = {**(packet.extra or {}), RELEASED_EXTRA: entry_id}
    TargetModel.sync_tlm_packet_counts(packet, target_names, scope=scope)
    TelemetryTopic.write_packet(packet, scope=scope)
    return packet.target_name, packet.packet_name
