"""DRAFT (Phase 2): the messages between EagleGate and the CryptoLib sidecar.

Nothing uses this yet. It fixes the wire format now so the sidecar (a separate
process or container linking NASA CryptoLib) and the SidecarCrypto backend can
be built against one definition, and so it is tested from the start.

Transport: a TCP or Unix socket. Each message is a 4-byte big-endian length,
then that many bytes of UTF-8 JSON. Binary fields are base64. One request, one
response, in order. The sidecar holds the keys and CryptoLib's SA table;
EagleGate never sends or receives key material.

  -> {"v": 1, "op": "hello"}
  <- {"v": 1, "ok": true, "cryptolib": "1.4.2", "sa_table": {"7": {"mode": "auth", ...}}}

  -> {"v": 1, "op": "tm_process", "id": 42, "spi": 7, "frame": "<base64 frame, no ASM>"}
  <- {"v": 1, "id": 42, "ok": true, "status": "verified", "data_field": "<base64>"}
  <- {"v": 1, "id": 42, "ok": false, "status": "failed", "detail": "MAC mismatch",
      "cryptolib_status": -12}

The sidecar must NOT do anti-replay (EagleGate does) and must not keep IV/ARSN
state that a rejected frame could change: "tm_process" is a pure check.
"""
import base64
import json
import struct

VERSION = 1
MAX_MESSAGE = 64 * 1024   # bytes of JSON; a frame is at most 2 KB before base64
OPS = ("hello", "tm_process")
STATUSES = ("verified", "decrypted", "failed")


class SidecarProtocolError(Exception):
    """A message that does not follow this protocol."""


def encode(message):
    """dict -> length-prefixed bytes."""
    body = json.dumps({"v": VERSION, **message}, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_MESSAGE:
        raise SidecarProtocolError(f"message of {len(body)} bytes exceeds {MAX_MESSAGE}")
    return struct.pack(">I", len(body)) + body


def decode(buffer):
    """(message, rest) for the first complete message in buffer, or (None, buffer)
    when more bytes are needed. Raises SidecarProtocolError for garbage."""
    if len(buffer) < 4:
        return None, buffer
    (length,) = struct.unpack(">I", buffer[:4])
    if length > MAX_MESSAGE:
        raise SidecarProtocolError(f"announced message of {length} bytes exceeds {MAX_MESSAGE}")
    if len(buffer) < 4 + length:
        return None, buffer
    try:
        message = json.loads(bytes(buffer[4:4 + length]).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SidecarProtocolError(f"not JSON: {error}") from None
    if not isinstance(message, dict) or message.get("v") != VERSION:
        raise SidecarProtocolError(f"not a version {VERSION} message")
    return message, buffer[4 + length:]


def tm_process_request(request_id, spi, frame):
    return {"op": "tm_process", "id": request_id, "spi": spi, "frame": base64.b64encode(frame).decode("ascii")}


def parse_tm_process_response(message, request_id):
    """-> (status, data_field or None, detail). Raises SidecarProtocolError."""
    if message.get("id") != request_id:
        raise SidecarProtocolError(f"response to request {message.get('id')!r}, expected {request_id}")
    status = message.get("status")
    if status not in STATUSES:
        raise SidecarProtocolError(f"unknown status {status!r}")
    ok = message.get("ok") is True
    if ok != (status != "failed"):
        raise SidecarProtocolError("'ok' contradicts 'status'")
    data_field = None
    if ok:
        try:
            data_field = base64.b64decode(message.get("data_field", ""), validate=True)
        except (ValueError, TypeError):
            raise SidecarProtocolError("data_field is not base64") from None
    detail = str(message.get("detail", ""))[:256]
    return status, data_field, detail
