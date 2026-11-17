"""The messages between EagleGate and the CryptoLib sidecar (wire protocol v1).

ONE definition for both ends: the sidecar image copies this file
(sidecar/Dockerfile in this plugin), the SidecarCrypto backend imports it.
Standard library only.

Transport: TCP. Each message is a 4-byte big-endian length, then that many
bytes of UTF-8 JSON. Binary fields are base64. One request, one response, in
order. The sidecar holds the keys and CryptoLib's SA table; EagleGate never
sends or receives key material (only SHA-256 fingerprints of keys).

Authentication (decision 3 in EagleGate/DECISIONS.md): HMAC-SHA256 (RFC 2104,
Python's hmac module) with a shared channel key, on requests AND responses.
No new cryptography: one standard MAC over a canonical form of each message.

  -> {"op": "hello", "kid": "default", "client_nonce": <16 random bytes>}
  <- {"op": "hello", "ok": true, "kid": ..., "client_nonce": ..., "server_nonce": ..., "mac": ...}

  The session is client_nonce + "." + server_nonce. Every later message
  carries "mac" = HMAC(key, canonical({"session", "dir", "msg"})) with dir
  "request" or "response" (and "hello" for the hello answer), so a message
  cannot be replayed into another session or reflected back. Request ids must
  increase within a session. A tm_process answer names the SHA-256 of the
  frame it is about, so it cannot be moved to another frame.

  -> {"op": "info", "id": 1, "mac": ...}
  <- {"op": "info", "id": 1, "ok": true, "sidecar": "0.2.0", "cryptolib": "1.5.1",
      "key_source": "internal", "security_associations": {"7": {...}}, "mac": ...}

  -> {"op": "tm_process", "id": 2, "frame": <frame, no ASM>, "mac": ...}
  <- {"op": "tm_process", "id": 2, "ok": true, "status": "verified", "spi": 7,
      "frame_sha256": ..., "data_field": <base64>, "cryptolib_status": 0, "mac": ...}

  -> {"op": "reload_keys", "id": 3, "mac": ...}
  <- {"op": "reload_keys", "id": 3, "ok": true, "loaded": 4, "problems": ["SPI 7: ..."],
      "detail": "...", "mac": ...}
     Re-reads the sidecar's key secret into CryptoLib's custom key ring
     (key_source "custom"; decision D12). Authenticated like every request;
     EagleGate sends it only for an admin request (RELOAD_KEYS). "ok": false
     when the keys were NOT changed (internal key source, unreadable file).
     Problems name key ids and SPIs, never key bytes.

  -> {"op": "health"}           (no session, no MAC: says only that it is up)
  <- {"op": "health", "ok": true}

The sidecar does NOT do anti-replay (EagleGate does) and keeps no IV/ARSN state
that a frame could change: tm_process is a pure check.
"""
import base64
import binascii
import hashlib
import hmac
import json
import secrets
import struct

VERSION = 1
MAX_MESSAGE = 256 * 1024  # bytes of JSON (an info answer lists every SA)
OPS = ("health", "hello", "info", "tm_process", "reload_keys")
MAX_PROBLEMS = 50
# tm_process statuses
VERIFIED = "verified"    # authentication-only SA: CryptoLib checked the MAC
DECRYPTED = "decrypted"  # encrypting SA: CryptoLib decrypted (and, for authenc, checked the tag)
CLEAR = "clear"          # clear SA: CryptoLib only parsed it
FAILED = "failed"        # CryptoLib refused the frame (bad MAC, decryption error, ...)
REFUSED = "refused"      # the sidecar refused it before CryptoLib (unknown SPI, wrong layout)
STATUSES = (VERIFIED, DECRYPTED, CLEAR, FAILED, REFUSED)
NONCE_BYTES = 16
MIN_KEY_BYTES = 32
MAX_DETAIL = 256


class SidecarProtocolError(Exception):
    """A message that does not follow this protocol (or fails authentication)."""


# ---- framing -----------------------------------------------------------------

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


def b64(data):
    return base64.b64encode(bytes(data)).decode("ascii")


def unb64(text, what):
    try:
        return base64.b64decode(text if isinstance(text, str) else "", validate=True)
    except (ValueError, binascii.Error):
        raise SidecarProtocolError(f"{what} is not base64") from None


# ---- authentication ----------------------------------------------------------

def parse_key(text):
    """The channel key from its hex text (an environment variable / secret).
    Raises ValueError without echoing the text."""
    try:
        key = bytes.fromhex(str(text).strip())
    except ValueError:
        raise ValueError("the sidecar channel key must be hex") from None
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"the sidecar channel key must be at least {MIN_KEY_BYTES} bytes "
                         f"({2 * MIN_KEY_BYTES} hex digits)")
    return key


def new_nonce():
    return b64(secrets.token_bytes(NONCE_BYTES))


def session_id(client_nonce, server_nonce):
    return f"{client_nonce}.{server_nonce}"


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _mac(key, session, direction, message):
    body = {k: v for k, v in message.items() if k != "mac"}
    body.setdefault("v", VERSION)
    return hmac.new(key, canonical({"session": session, "dir": direction, "msg": body}), hashlib.sha256).hexdigest()


def sign(key, session, direction, message):
    """message with its "mac" added."""
    return {**message, "mac": _mac(key, session, direction, message)}


def verify(key, session, direction, message):
    mac = message.get("mac")
    return isinstance(mac, str) and hmac.compare_digest(mac, _mac(key, session, direction, message))


# ---- hello -------------------------------------------------------------------

def hello_request(kid, client_nonce):
    return {"op": "hello", "kid": kid, "client_nonce": client_nonce}


def hello_response(key, kid, client_nonce, server_nonce):
    """The sidecar's answer, signed for the new session."""
    message = {"op": "hello", "ok": True, "kid": kid, "client_nonce": client_nonce, "server_nonce": server_nonce}
    return sign(key, session_id(client_nonce, server_nonce), "hello", message)


def parse_hello_response(message, key, kid, client_nonce):
    """-> the session id. Raises SidecarProtocolError (wrong key, wrong nonce, refused)."""
    if message.get("op") != "hello":
        raise SidecarProtocolError(f"expected a hello answer, got {message.get('op')!r}")
    if message.get("ok") is not True:
        raise SidecarProtocolError(f"hello refused: {_detail(message)}")
    if message.get("kid") != kid or message.get("client_nonce") != client_nonce:
        raise SidecarProtocolError("hello answer is for another key id or nonce")
    server_nonce = message.get("server_nonce")
    if not isinstance(server_nonce, str) or len(unb64(server_nonce, "server_nonce")) != NONCE_BYTES:
        raise SidecarProtocolError("hello answer has no valid server nonce")
    session = session_id(client_nonce, server_nonce)
    if not verify(key, session, "hello", message):
        raise SidecarProtocolError("hello answer failed authentication (different channel key?)")
    return session


# ---- requests and answers ----------------------------------------------------

def info_request(request_id):
    return {"op": "info", "id": request_id}


def tm_process_request(request_id, frame):
    return {"op": "tm_process", "id": request_id, "frame": b64(frame)}


def reload_keys_request(request_id):
    return {"op": "reload_keys", "id": request_id}


def reload_keys_response(request_id, ok, loaded, problems, detail):
    return {"op": "reload_keys", "id": request_id, "ok": bool(ok), "loaded": int(loaded),
            "problems": [str(p)[:MAX_DETAIL] for p in problems][:MAX_PROBLEMS], "detail": str(detail)[:MAX_DETAIL]}


def parse_reload_keys_response(message):
    """-> (ok, loaded, problems, detail). Call check_response first."""
    ok = message.get("ok")
    loaded = message.get("loaded")
    problems = message.get("problems")
    if not isinstance(ok, bool) or not isinstance(loaded, int) or isinstance(loaded, bool):
        raise SidecarProtocolError("malformed reload_keys answer")
    if not isinstance(problems, list) or not all(isinstance(p, str) for p in problems):
        raise SidecarProtocolError("reload_keys problems must be a list of text")
    return ok, loaded, [p[:MAX_DETAIL] for p in problems[:MAX_PROBLEMS]], _detail(message)


def frame_sha256(frame):
    return hashlib.sha256(bytes(frame)).hexdigest()


def tm_process_response(request_id, frame, status, spi=None, data_field=None, cryptolib_status=None, detail=""):
    message = {"op": "tm_process", "id": request_id, "ok": status in (VERIFIED, DECRYPTED, CLEAR),
               "status": status, "spi": spi, "frame_sha256": frame_sha256(frame),
               "cryptolib_status": cryptolib_status, "detail": str(detail)[:MAX_DETAIL]}
    if data_field is not None:
        message["data_field"] = b64(data_field)
    return message


def check_response(message, key, session, op, request_id):
    """Authenticate an answer and check it answers this request."""
    if not verify(key, session, "response", message):
        raise SidecarProtocolError("answer failed authentication")
    if message.get("op") != op or message.get("id") != request_id:
        raise SidecarProtocolError(f"answer to {message.get('op')!r} {message.get('id')!r}, "
                                   f"expected {op!r} {request_id}")


def parse_tm_process_response(message, request_id, frame):
    """-> (status, spi, data_field or None, cryptolib_status, detail). Call
    check_response first. Raises SidecarProtocolError."""
    if message.get("id") != request_id:
        raise SidecarProtocolError(f"response to request {message.get('id')!r}, expected {request_id}")
    if message.get("frame_sha256") != frame_sha256(frame):
        raise SidecarProtocolError("answer is about a different frame")
    status = message.get("status")
    if status not in STATUSES:
        raise SidecarProtocolError(f"unknown status {status!r}")
    ok = message.get("ok") is True
    if ok != (status in (VERIFIED, DECRYPTED, CLEAR)):
        raise SidecarProtocolError("'ok' contradicts 'status'")
    data_field = unb64(message.get("data_field"), "data_field") if ok else None
    spi = message.get("spi")
    if spi is not None and not isinstance(spi, int):
        raise SidecarProtocolError("spi is not a number")
    cryptolib_status = message.get("cryptolib_status")
    if cryptolib_status is not None and not isinstance(cryptolib_status, int):
        raise SidecarProtocolError("cryptolib_status is not a number")
    return status, spi, data_field, cryptolib_status, _detail(message)


def _detail(message):
    return str(message.get("detail", ""))[:MAX_DETAIL]
