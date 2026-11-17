"""SidecarCrypto (eaglegate_sdls_sidecar_backend) against the sidecar's real
server code (../sidecar) over real TCP sockets, with a stand-in
for CryptoLib. CryptoLib itself is tested in the sidecar's test image."""
import hashlib
import os
import socket
import sys
import threading

import pytest

import eaglegate_sdls_sidecar_protocol as wire
from conftest import shipped_rules
from eaglegate_sdls_frame_security import (CLEAR, DECRYPTED, FAILED, REFUSED, UNAVAILABLE, UNREADABLE, UNVERIFIED,
                                           VERIFIED)
from eaglegate_sdls_link_config import parse_link_config
from eaglegate_sdls_sidecar_backend import SidecarCrypto
from eaglegate_sdls_tm_frame import PrimaryHeader, parse_tm_frame
from sdls_frames import Layout, build_frame, packet

SIDECAR_DIR = os.path.join(os.path.dirname(__file__), "..", "sidecar")
pytestmark = pytest.mark.skipif(not os.path.isdir(SIDECAR_DIR), reason="sidecar folder not found")
if os.path.isdir(SIDECAR_DIR):
    sys.path.insert(0, SIDECAR_DIR)

KEY = bytes(range(32))
TEST_KEY = bytes([0x13]) * 32
KNOWN_TEST_KEYS = frozenset({hashlib.sha256(TEST_KEY).hexdigest()})
SIDECAR_SAS = {
    "5": {"vcid": 1, "service": "clear", "iv_len": 12},
    "6": {"vcid": 4, "service": "enc", "ecs": "AES256_GCM", "ekid": 9, "iv_len": 12},
    "7": {"vcid": 5, "service": "auth", "acs": "HMAC_SHA256", "akid": 130, "sn_len": 2, "mac_len": 16,
          "abm": "ones"},
}


class FakeEngine:
    """CryptoLib stand-in: a frame whose last data byte is 0xBA "fails"; key
    130 is a "test key"; the data field comes back as is."""

    version = "1.5.1-fake"

    def __init__(self, config):
        self.config = config
        self.calls = 0

    def key(self, key_id):
        return bytearray(TEST_KEY if key_id == 130 else bytes([key_id]) * 32), "active"

    def status_name(self, status):
        return "CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR"

    def process(self, frame):
        self.calls += 1
        tm = self.config.tm
        spi = int.from_bytes(frame[6:8], "big")
        sa = self.config.sas[spi]
        start, end = 6 + sa.header_length(), tm.frame_length - sa.mac_len
        if frame[end - 1] == 0xBA:
            return -1, spi, None
        return 0, spi, bytes(frame[start:end])


class Sidecar:
    """The real sidecar server (eaglegate_sidecar.server) on a free localhost port."""

    def __init__(self, sas=None, keys=None, known=KNOWN_TEST_KEYS):
        from eaglegate_sidecar import config as cfg
        from eaglegate_sidecar.server import Sidecar as Logic
        from eaglegate_sidecar.server import SidecarServer

        config = cfg.parse({"tm": {"scid": 3, "frame_length": 1786}, "security_associations": sas or SIDECAR_SAS})
        self.engine = FakeEngine(config)
        self.logic = Logic(config, self.engine, keys or {"default": KEY}, known)
        self.server = SidecarServer(("127.0.0.1", 0), self.logic)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.close_connections()
        self.server.server_close()


@pytest.fixture
def sidecar():
    server = Sidecar()
    yield server
    server.stop()


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def link(port, crypto=None, **sa_changes):
    raw = shipped_rules()["link"]
    raw = {**raw, "security_associations": {k: dict(v) for k, v in raw["security_associations"].items()},
           "crypto": {"backend": "sidecar", "host": "127.0.0.1", "port": port, "timeout_ms": 300, **(crypto or {})}}
    for spi, changes in sa_changes.items():
        raw["security_associations"][spi.lstrip("_")].update(changes)
    return parse_link_config(raw)


def backend(config, env=None, clock=None):
    return SidecarCrypto(config.crypto, config, "TEST_INT", env={"EAGLEGATE_SIDECAR_KEY": KEY.hex()}
                         if env is None else env, clock=clock or Clock())


def tm(config, spi, vcid, payload=b"hello", sn=None, iv=None, mac=None, last=None):
    layout = Layout.for_spi(spi)
    data = packet(0x22, payload)
    field = data + bytes(layout.data_length() - len(data))
    if last is not None:
        field = field[:-1] + bytes([last])
    raw = build_frame(field, 0, spi=spi, vcid=vcid, layout=layout, sn=sn, iv=iv, mac=mac)
    return parse_tm_frame(raw, PrimaryHeader.from_bytes(raw), config.sas[spi], config.has_fecf)


def test_verified_frame_with_a_full_mask(sidecar):
    config = link(sidecar.port)
    crypto = backend(config)
    frame = tm(config, 7, 5, sn=1)
    result = crypto.process(frame, config.sas[7])
    assert (result.status, result.protection, result.counter_verified, result.pad_removed) == \
        (VERIFIED, "auth", True, True)
    assert result.data_field == frame.data_field
    assert result.key_epoch == f"a130:{hashlib.sha256(TEST_KEY).hexdigest()[:16]}"
    status = crypto.status()
    assert status["connected"] and status["cryptolib"] == "1.5.1-fake" and status["sa_match"]
    assert status["test_key_spis"] == [7]
    assert crypto.sa_keys()["7"]["test_key"] is True


def test_decrypted_frame(sidecar):
    config = link(sidecar.port)
    result = backend(config).process(tm(config, 6, 4, iv=5), config.sas[6])
    assert (result.status, result.protection, result.counter_verified) == (DECRYPTED, "enc", False)


def test_clear_frames_are_never_sent(sidecar):
    config = link(sidecar.port)
    result = backend(config).process(tm(config, 5, 1), config.sas[5])
    assert result.status == CLEAR and sidecar.engine.calls == 0


def test_cryptolib_refusal_is_failed(sidecar):
    config = link(sidecar.port)
    result = backend(config).process(tm(config, 7, 5, sn=1, last=0xBA), config.sas[7])
    assert result.status == FAILED and "MAC_VALIDATION" in result.detail


def test_zero_mask_mac_does_not_count_as_authentication():
    server = Sidecar(sas={**SIDECAR_SAS, "7": {**SIDECAR_SAS["7"], "abm": "zeros"}})
    try:
        config = link(server.port)
        crypto = backend(config)
        result = crypto.process(tm(config, 7, 5, sn=1), config.sas[7])
        assert (result.status, result.protection, result.counter_verified) == (UNVERIFIED, "auth_unverified", False)
        assert "does not cover the data field" in result.warnings[0]
        assert crypto.sa_keys()["7"]["mask_covers_data"] is False
    finally:
        server.stop()


def test_sa_table_must_match_the_rules(sidecar):
    cases = {"sn_len": link(sidecar.port, _7={"sn_len": 4}),
             "akid": link(sidecar.port, _7={"akid": 131}),
             "ekid": link(sidecar.port, _6={"ekid": 10})}
    for name, config in cases.items():
        spi = 6 if name == "ekid" else 7
        crypto = backend(config)
        result = crypto.process(tm(config, spi, 4 if spi == 6 else 5, sn=1, iv=1), config.sas[spi])
        assert result.status == REFUSED and name in result.detail, name
        assert crypto.status()["sa_match"] is False
    matching = link(sidecar.port, _7={"akid": 130}, _6={"ekid": 9})
    assert backend(matching).process(tm(matching, 7, 5, sn=1), matching.sas[7]).status == VERIFIED


def test_test_keys_can_be_denied(sidecar):
    config = link(sidecar.port, crypto={"test_keys": "deny"})
    crypto = backend(config)
    result = crypto.process(tm(config, 7, 5, sn=1), config.sas[7])
    assert result.status == REFUSED and "test keys" in result.detail
    assert crypto.process(tm(config, 6, 4, iv=1), config.sas[6]).status == DECRYPTED  # key 9 is not a test key


def test_without_the_channel_key_nothing_is_verified(sidecar):
    config = link(sidecar.port)
    result = backend(config, env={}).process(tm(config, 7, 5, sn=1), config.sas[7])
    assert result.status == UNAVAILABLE and "EAGLEGATE_SIDECAR_KEY" in result.detail
    wrong = backend(config, env={"EAGLEGATE_SIDECAR_KEY": bytes(32).hex()})
    result = wrong.process(tm(config, 7, 5, sn=1), config.sas[7])
    assert result.status == UNAVAILABLE and "authentication" in result.detail


def test_unknown_key_id(sidecar):
    config = link(sidecar.port, crypto={"key_id": "other"})
    result = backend(config).process(tm(config, 7, 5, sn=1), config.sas[7])
    assert result.status == UNAVAILABLE and "unknown key id" in result.detail


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_unreachable_sidecar_fails_closed_or_unverified_with_backoff():
    port = free_port()
    config = link(port)
    clock = Clock()
    crypto = backend(config, clock=clock)
    assert crypto.process(tm(config, 7, 5, sn=1), config.sas[7]).status == UNAVAILABLE
    assert crypto.counts["connects"] == 0 and crypto.down_until == clock.now + 1.0
    crypto.process(tm(config, 7, 5, sn=1), config.sas[7])
    assert crypto.backoff == 2.0  # no new attempt inside the backoff
    lenient = link(port, crypto={"on_unavailable": "unverified"})
    soft = backend(lenient)
    assert soft.process(tm(lenient, 7, 5, sn=1), lenient.sas[7]).status == UNVERIFIED
    assert soft.process(tm(lenient, 6, 4, iv=1), lenient.sas[6]).status == UNREADABLE


def test_reconnects_after_the_sidecar_restarts():
    first = Sidecar()
    port = first.port
    config = link(port)
    clock = Clock()
    crypto = backend(config, clock=clock)
    assert crypto.process(tm(config, 7, 5, sn=1), config.sas[7]).status == VERIFIED
    first.stop()
    assert crypto.process(tm(config, 7, 5, sn=2), config.sas[7]).status == UNAVAILABLE
    from eaglegate_sidecar.server import SidecarServer

    second = Sidecar()
    second.stop()
    second.server = SidecarServer(("127.0.0.1", port), second.logic)
    threading.Thread(target=second.server.serve_forever, daemon=True).start()
    try:
        clock.now += 5
        assert crypto.process(tm(config, 7, 5, sn=3), config.sas[7]).status == VERIFIED
        assert crypto.counts["connects"] == 2
    finally:
        second.stop()


class Rogue:
    """A fake sidecar: completes hello with the right key (it stole it? no:
    `key` decides), then answers tm_process with whatever `answer` makes."""

    def __init__(self, key, answer):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.key, self.answer = key, answer
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        conn, _ = self.listener.accept()
        buffer, session = b"", None
        with conn:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buffer += chunk
                while True:
                    message, buffer = wire.decode(buffer)
                    if message is None:
                        break
                    if message["op"] == "hello":
                        server_nonce = wire.new_nonce()
                        session = wire.session_id(message["client_nonce"], server_nonce)
                        reply = wire.hello_response(self.key, message["kid"], message["client_nonce"], server_nonce)
                    elif message["op"] == "info":
                        reply = wire.sign(self.key, session, "response", {
                            "op": "info", "id": message["id"], "ok": True,
                            "security_associations": {"7": {"vcid": 5, "service": "auth", "iv_len": 0, "sn_len": 2,
                                                            "pl_len": 0, "mac_len": 16, "keys": {},
                                                            "mask": {"data_field": True,
                                                                     "sequence_number": True}}}})
                    else:
                        reply = self.answer(self.key, session, message)
                    if reply is None:
                        continue  # never answer: a timeout
                    conn.sendall(wire.encode(reply))


def test_a_forged_verified_answer_is_refused():
    def forged(key, session, message):
        frame = wire.unb64(message["frame"], "frame")
        answer = wire.tm_process_response(message["id"], frame, wire.VERIFIED, spi=7,
                                          data_field=frame[8:-16], cryptolib_status=0)
        return wire.sign(bytes(32), session, "response", answer)  # not the channel key

    rogue = Rogue(KEY, forged)
    config = link(rogue.port)
    result = backend(config).process(tm(config, 7, 5, sn=1), config.sas[7])
    assert result.status == UNAVAILABLE and "authentication" in result.detail


def test_an_answer_about_another_frame_or_with_other_data_is_refused():
    def other_frame(key, session, message):
        answer = wire.tm_process_response(message["id"], b"other", wire.VERIFIED, spi=7, data_field=b"x",
                                          cryptolib_status=0)
        return wire.sign(key, session, "response", answer)

    rogue = Rogue(KEY, other_frame)
    config = link(rogue.port)
    result = backend(config).process(tm(config, 7, 5, sn=1), config.sas[7])
    assert result.status == UNAVAILABLE and "different frame" in result.detail

    def other_data(key, session, message):
        frame = wire.unb64(message["frame"], "frame")
        answer = wire.tm_process_response(message["id"], frame, wire.VERIFIED, spi=7,
                                          data_field=bytes(len(frame) - 6 - 2 - 2 - 16), cryptolib_status=0)
        return wire.sign(key, session, "response", answer)

    rogue = Rogue(KEY, other_data)
    config = link(rogue.port)
    result = backend(config).process(tm(config, 7, 5, sn=1), config.sas[7])
    assert result.status == FAILED and "other data" in result.detail


def test_a_silent_sidecar_times_out():
    rogue = Rogue(KEY, lambda key, session, message: None)
    config = link(rogue.port, crypto={"timeout_ms": 50})
    crypto = backend(config)
    result = crypto.process(tm(config, 7, 5, sn=1), config.sas[7])
    assert result.status == UNAVAILABLE and "no answer within 50 ms" in result.detail
    assert crypto.counts["timeouts"] == 1


# ---- key reload (decision D12) -----------------------------------------------------

class CustomEngine(FakeEngine):
    """FakeEngine with a custom key ring the sidecar can reload."""

    custom = True

    def __init__(self, config):
        super().__init__(config)
        self.load_problems = []
        self.ring = {9: bytes([9]) * 32, 130: bytes([1]) * 32}

    def load_keys(self, keys):
        self.ring = {key_id: bytes(value) for key_id, value, _ in keys}
        return []

    def key(self, key_id):
        return bytearray(self.ring.get(key_id, b"")), "active"

    def expected_key_length(self, kind, suite):
        return 32


@pytest.fixture
def custom_sidecar(tmp_path):
    import json as json_

    from eaglegate_sidecar import config as cfg
    from eaglegate_sidecar.server import Sidecar as Logic
    from eaglegate_sidecar.server import SidecarServer

    key_file = tmp_path / "keys.json"
    key_file.write_text(json_.dumps({"keys": [{"id": 9, "hex": "09" * 32}, {"id": 130, "hex": "01" * 32}]}))
    config = cfg.parse({"tm": {"scid": 3, "frame_length": 1786}, "key_source": "custom",
                        "security_associations": SIDECAR_SAS})
    logic = Logic(config, CustomEngine(config), {"default": KEY}, KNOWN_TEST_KEYS, str(key_file), [])
    server = SidecarServer(("127.0.0.1", 0), logic)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server, key_file
    server.shutdown()
    server.close_connections()
    server.server_close()


def test_reload_keys_uses_its_own_session_and_new_fingerprints_follow(custom_sidecar):
    import json as json_

    server, key_file = custom_sidecar
    config = link(server.server_address[1])
    crypto = backend(config)
    assert crypto._ready()
    before = crypto.key_epoch(7)
    key_file.write_text(json_.dumps({"keys": [{"id": 9, "hex": "09" * 32}, {"id": 130, "hex": "02" * 32}]}))
    ok, detail, problems = crypto.reload_keys()
    assert (ok, problems) == (True, []) and detail == "2 key(s) loaded"
    assert crypto.session is not None  # the read thread's session was not touched
    assert crypto.info_stale
    assert crypto._ready() and not crypto.info_stale
    assert crypto.key_epoch(7) != before  # a new key: EagleGate starts a new anti-replay baseline
    assert crypto.status()["key_reloads"] == 1


def test_reload_keys_reports_problems_and_refusals(custom_sidecar):
    import json as json_

    server, key_file = custom_sidecar
    crypto = backend(link(server.server_address[1]))
    key_file.write_text(json_.dumps({"keys": [{"id": 130, "hex": "02" * 32}]}))
    ok, _, problems = crypto.reload_keys()
    assert ok and problems == ["SPI 6: its encryption key 9 is not loaded"]
    assert crypto._ready() and crypto.status()["key_problems"] == "SPI 6: its encryption key 9 is not loaded"
    key_file.write_text("{ broken")
    ok, detail, _ = crypto.reload_keys()
    assert not ok and "keys unchanged" in detail


def test_reload_keys_without_a_sidecar_or_channel_key():
    port = free_port()
    crypto = backend(link(port))
    ok, detail, _ = crypto.reload_keys()
    assert not ok and "no answer from the sidecar" in detail
    keyless = backend(link(port), env={})
    assert keyless.reload_keys()[0] is False
