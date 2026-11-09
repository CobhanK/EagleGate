"""The Phase 2 sidecar message format (eaglegate_sdls_sidecar_protocol), fixed now."""
import base64
import struct

import pytest

from eaglegate_sdls_sidecar_protocol import (MAX_MESSAGE, SidecarProtocolError, decode, encode,
                                             parse_tm_process_response, tm_process_request)


def test_request_round_trip_in_pieces():
    wire = encode(tm_process_request(42, 7, b"\x00\x01frame"))
    message, rest = decode(wire[:3])
    assert message is None and rest == wire[:3]
    message, rest = decode(wire + b"extra")
    assert message == {"v": 1, "op": "tm_process", "id": 42, "spi": 7,
                       "frame": base64.b64encode(b"\x00\x01frame").decode()}
    assert rest == b"extra"


def test_two_messages_in_one_buffer():
    wire = encode({"op": "hello"}) + encode({"op": "hello", "x": 1})
    first, rest = decode(wire)
    second, rest = decode(rest)
    assert first["op"] == second["op"] == "hello" and second["x"] == 1 and rest == b""


@pytest.mark.parametrize("wire, message", [
    (struct.pack(">I", MAX_MESSAGE + 1), "exceeds"),
    (struct.pack(">I", 3) + b"{x}", "not JSON"),
    (struct.pack(">I", 2) + b"[]", "not a version 1 message"),
    (struct.pack(">I", 8) + b'{"v": 2}', "not a version 1 message"),
])
def test_garbage_is_refused(wire, message):
    with pytest.raises(SidecarProtocolError, match=message):
        decode(wire)


def test_oversized_message_cannot_be_encoded():
    with pytest.raises(SidecarProtocolError, match="exceeds"):
        encode({"op": "tm_process", "frame": "A" * MAX_MESSAGE})


def test_responses():
    ok = {"v": 1, "id": 3, "ok": True, "status": "verified", "data_field": base64.b64encode(b"plain").decode()}
    assert parse_tm_process_response(ok, 3) == ("verified", b"plain", "")
    failed = {"v": 1, "id": 3, "ok": False, "status": "failed", "detail": "MAC mismatch" * 100}
    status, data, detail = parse_tm_process_response(failed, 3)
    assert (status, data) == ("failed", None) and len(detail) == 256


@pytest.mark.parametrize("response, message", [
    ({"id": 4, "ok": True, "status": "verified"}, "response to request 4"),
    ({"id": 3, "ok": True, "status": "maybe"}, "unknown status"),
    ({"id": 3, "ok": False, "status": "verified"}, "contradicts"),
    ({"id": 3, "ok": True, "status": "failed"}, "contradicts"),
    ({"id": 3, "ok": True, "status": "verified", "data_field": "***"}, "not base64"),
])
def test_bad_responses(response, message):
    with pytest.raises(SidecarProtocolError, match=message):
        parse_tm_process_response({"v": 1, **response}, 3)
