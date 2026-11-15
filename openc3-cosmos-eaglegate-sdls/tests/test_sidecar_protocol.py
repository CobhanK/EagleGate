"""Wire protocol v1 between EagleGate and the CryptoLib sidecar
(eaglegate_sdls_sidecar_protocol): framing and HMAC-SHA256 authentication."""
import struct

import pytest

import eaglegate_sdls_sidecar_protocol as wire
from eaglegate_sdls_sidecar_protocol import (MAX_MESSAGE, SidecarProtocolError, decode, encode,
                                             parse_tm_process_response, tm_process_request)

KEY = bytes(range(32))
FRAME = b"\x00\x01frame"


def test_request_round_trip_in_pieces():
    data = encode(tm_process_request(42, FRAME))
    message, rest = decode(data[:3])
    assert message is None and rest == data[:3]
    message, rest = decode(data + b"extra")
    assert message == {"v": 1, "op": "tm_process", "id": 42, "frame": wire.b64(FRAME)}
    assert rest == b"extra"


def test_two_messages_in_one_buffer():
    data = encode({"op": "hello"}) + encode({"op": "hello", "x": 1})
    first, rest = decode(data)
    second, rest = decode(rest)
    assert first["op"] == second["op"] == "hello" and second["x"] == 1 and rest == b""


@pytest.mark.parametrize("data, message", [
    (struct.pack(">I", MAX_MESSAGE + 1), "exceeds"),
    (struct.pack(">I", 3) + b"{x}", "not JSON"),
    (struct.pack(">I", 2) + b"[]", "not a version 1 message"),
    (struct.pack(">I", 8) + b'{"v": 2}', "not a version 1 message"),
])
def test_garbage_is_refused(data, message):
    with pytest.raises(SidecarProtocolError, match=message):
        decode(data)


def test_oversized_message_cannot_be_encoded():
    with pytest.raises(SidecarProtocolError, match="exceeds"):
        encode({"op": "tm_process", "frame": "A" * MAX_MESSAGE})


def test_channel_key():
    assert wire.parse_key(KEY.hex() + "\n") == KEY
    for bad in ("", "abcd", "zz" * 32, None):
        with pytest.raises(ValueError, match="channel key"):
            wire.parse_key(bad)


def session():
    client_nonce = wire.new_nonce()
    answer = wire.hello_response(KEY, "default", client_nonce, wire.new_nonce())
    return wire.parse_hello_response(answer, KEY, "default", client_nonce), client_nonce, answer


def test_hello_establishes_a_session_only_with_the_right_key():
    sid, client_nonce, answer = session()
    assert sid.startswith(client_nonce + ".")
    with pytest.raises(SidecarProtocolError, match="authentication"):
        wire.parse_hello_response(answer, bytes(32), "default", client_nonce)
    with pytest.raises(SidecarProtocolError, match="another key id or nonce"):
        wire.parse_hello_response(answer, KEY, "default", wire.new_nonce())  # an old answer, replayed
    with pytest.raises(SidecarProtocolError, match="refused"):
        wire.parse_hello_response({"op": "hello", "ok": False, "detail": "unknown key id"}, KEY, "x", client_nonce)


def test_messages_are_bound_to_session_direction_and_content():
    sid, _, _ = session()
    other, _, _ = session()
    message = wire.sign(KEY, sid, "response", wire.tm_process_response(3, FRAME, wire.VERIFIED, spi=7,
                                                                       data_field=b"plain", cryptolib_status=0))
    wire.check_response(message, KEY, sid, "tm_process", 3)
    for bad_session, direction in ((other, "response"), (sid, "request")):
        assert not wire.verify(KEY, bad_session, direction, message)
    changed = {**message, "status": wire.DECRYPTED}
    with pytest.raises(SidecarProtocolError, match="authentication"):
        wire.check_response(changed, KEY, sid, "tm_process", 3)
    with pytest.raises(SidecarProtocolError, match="expected 'tm_process' 4"):
        wire.check_response(message, KEY, sid, "tm_process", 4)


def test_responses():
    ok = wire.tm_process_response(3, FRAME, wire.VERIFIED, spi=7, data_field=b"plain", cryptolib_status=0)
    assert parse_tm_process_response(ok, 3, FRAME) == ("verified", 7, b"plain", 0, "")
    failed = wire.tm_process_response(3, FRAME, wire.FAILED, spi=7, cryptolib_status=-12, detail="MAC" * 200)
    status, spi, data, cryptolib_status, detail = parse_tm_process_response(failed, 3, FRAME)
    assert (status, data, cryptolib_status) == ("failed", None, -12) and len(detail) == 256
    with pytest.raises(SidecarProtocolError, match="different frame"):
        parse_tm_process_response(ok, 3, FRAME + b"x")


@pytest.mark.parametrize("change, message", [
    ({"id": 4}, "response to request 4"),
    ({"status": "maybe"}, "unknown status"),
    ({"ok": False}, "contradicts"),
    ({"status": "failed"}, "contradicts"),
    ({"data_field": "***"}, "not base64"),
    ({"spi": "7"}, "spi is not a number"),
])
def test_bad_responses(change, message):
    good = wire.tm_process_response(3, FRAME, wire.VERIFIED, spi=7, data_field=b"plain", cryptolib_status=0)
    with pytest.raises(SidecarProtocolError, match=message):
        parse_tm_process_response({**good, **change}, 3, FRAME)
