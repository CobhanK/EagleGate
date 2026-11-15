"""The sidecar's own logic, with a stand-in for CryptoLib (runs anywhere).
The real CryptoLib is exercised by test_cryptolib.py in the test image."""
import json
import unittest

from tests import _paths  # noqa: F401  (sys.path)

import eaglegate_sdls_sidecar_protocol as wire
from sidecar import config as cfg
from sidecar import keys as key_info
from sidecar.server import Sidecar, channel_keys_from_env

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
TEST_KEY_130 = bytes(range(32))  # stand-in "test key"


class FakeEngine:
    """Behaves like CryptoLibEngine without CryptoLib: frames whose last data
    byte is 0xBA "fail"; the data field is returned as is."""

    version = "0.0.0-fake"

    def __init__(self, sidecar_config):
        self.config = sidecar_config
        self.calls = 0

    def key(self, key_id):
        return bytearray(TEST_KEY_130 if key_id == 130 else bytes([key_id]) * 32), "active"

    def status_name(self, status):
        return {-1: "CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR"}.get(status, str(status))

    def process(self, frame):
        self.calls += 1
        tm = self.config.tm
        spi = int.from_bytes(frame[tm.spi_offset:tm.spi_offset + 2], "big")
        sa = self.config.sas[spi]
        start = tm.spi_offset + sa.header_length()
        end = tm.frame_length - sa.mac_len
        if frame[end - 1] == 0xBA:
            return -1, spi, None
        return 0, spi, bytes(frame[start:end])


def nos3_config():
    return cfg.load(_paths.NOS3_CONFIG)


def frame(vcid, spi, fill=0x11, length=1786, scid=3):
    data = bytearray([fill]) * length
    data[0] = (scid >> 4) & 0x3F
    data[1] = ((scid & 0x0F) << 4) | (vcid << 1)
    data[4], data[5] = 0x18, 0x00
    data[6:8] = spi.to_bytes(2, "big")
    return bytes(data)


class Client:
    """The EagleGate side of a session, against Sidecar.handle (no sockets)."""

    def __init__(self, sidecar, key=KEY, kid="default"):
        self.sidecar, self.key, self.kid = sidecar, key, kid
        self.state = sidecar.new_session()
        self.next_id = 1
        nonce = wire.new_nonce()
        answer = sidecar.handle(wire.hello_request(kid, nonce), self.state)
        self.session = wire.parse_hello_response(answer, key, kid, nonce)

    def call(self, request):
        request = wire.sign(self.key, self.session, "request", request)
        answer = self.sidecar.handle(request, self.state)
        wire.check_response(answer, self.key, self.session, request["op"], request["id"])
        return answer

    def process(self, data):
        request_id, self.next_id = self.next_id, self.next_id + 1
        answer = self.call(wire.tm_process_request(request_id, data))
        return wire.parse_tm_process_response(answer, request_id, data)

    def info(self):
        request_id, self.next_id = self.next_id, self.next_id + 1
        return self.call(wire.info_request(request_id))


def make_sidecar(known=None):
    config = nos3_config()
    return Sidecar(config, FakeEngine(config), {"default": KEY}, known)


class ConfigTest(unittest.TestCase):
    def test_nos3_config_matches_the_flight_sas(self):
        config = nos3_config()
        self.assertEqual(sorted(config.sas), [5, 6, 7])
        auth = config.sas[7]
        self.assertEqual((auth.vcid, auth.service, auth.acs, auth.akid, auth.sn_len, auth.mac_len),
                         (5, "auth", "HMAC_SHA256", 130, 2, 16))
        self.assertEqual(auth.abm, bytes(1786))  # NOS3 never sets the mask: all zeros
        enc = config.sas[6]
        self.assertEqual((enc.vcid, enc.ecs, enc.ekid, enc.iv_len, enc.mac_len), (4, "AES256_GCM", 9, 12, 0))
        self.assertEqual(config.channels, [1, 4, 5])

    def test_combinations_cryptolib_does_not_check_are_refused(self):
        base = {"tm": {"scid": 3, "frame_length": 1786}}
        bad = {
            "auth with an AEAD cipher (CryptoLib would not check it)": {
                "vcid": 5, "service": "auth", "ecs": "AES256_GCM", "acs": "HMAC_SHA256", "mac_len": 16, "abm": "ones"},
            "auth without a mask": {"vcid": 5, "service": "auth", "acs": "HMAC_SHA256", "mac_len": 16},
            "auth without a MAC": {"vcid": 5, "service": "auth", "acs": "HMAC_SHA256", "abm": "ones"},
            "clear with a MAC": {"vcid": 1, "service": "clear", "mac_len": 16},
            "GCM with an 8-byte IV": {"vcid": 4, "service": "enc", "ecs": "AES256_GCM", "iv_len": 8},
            "unknown key": {"vcid": 1, "service": "clear", "colour": "red"},
            "VC out of range": {"vcid": 8, "service": "clear"},
        }
        for name, sa in bad.items():
            with self.subTest(name), self.assertRaises(cfg.ConfigError):
                cfg.parse({**base, "security_associations": {"7": sa}})
        with self.assertRaises(cfg.ConfigError):
            cfg.parse({**base, "security_associations": {"0": {"vcid": 1, "service": "clear"}}})

    def test_abm_forms(self):
        tm = {"scid": 3, "frame_length": 100}
        sa = {"vcid": 5, "service": "auth", "acs": "HMAC_SHA256", "mac_len": 16}
        ones = cfg.parse({"tm": tm, "security_associations": {"7": {**sa, "abm": "ones"}}}).sas[7]
        self.assertEqual(ones.abm, b"\xff" * 100)
        partial = cfg.parse({"tm": tm, "security_associations": {"7": {**sa, "abm": "FFFF"}}}).sas[7]
        self.assertEqual(partial.abm, b"\xff\xff" + bytes(98))


class MaskCoverageTest(unittest.TestCase):
    def test_nos3_zero_mask_covers_nothing(self):
        config = nos3_config()
        coverage = key_info.mask_coverage(config.sas[7], config.tm)
        self.assertEqual(coverage, {"mask_bytes": 1786, "primary_header": 0.0, "spi": False,
                                    "sequence_number": False, "data_field": False})
        self.assertIsNone(key_info.mask_coverage(config.sas[6], config.tm))  # not authenticated

    def test_full_mask_covers_everything(self):
        config = cfg.parse({"tm": {"scid": 3, "frame_length": 1786}, "security_associations": {"7": {
            "vcid": 5, "service": "auth", "acs": "HMAC_SHA256", "sn_len": 2, "mac_len": 16, "abm": "ones"}}})
        coverage = key_info.mask_coverage(config.sas[7], config.tm)
        self.assertEqual((coverage["primary_header"], coverage["spi"], coverage["sequence_number"],
                          coverage["data_field"]), (1.0, True, True, True))

    def test_header_only_mask(self):
        config = cfg.parse({"tm": {"scid": 3, "frame_length": 1786}, "security_associations": {"7": {
            "vcid": 5, "service": "auth", "acs": "HMAC_SHA256", "sn_len": 2, "mac_len": 16, "abm": "FF" * 10}}})
        coverage = key_info.mask_coverage(config.sas[7], config.tm)
        self.assertEqual((coverage["sequence_number"], coverage["data_field"]), (True, False))


class FingerprintTest(unittest.TestCase):
    def test_fingerprint_is_sha256_and_key_is_wiped(self):
        import hashlib

        engine = FakeEngine(nos3_config())
        held = {}
        original = engine.key

        def key(key_id):
            held["key"] = original(key_id)[0]
            return held["key"], "active"

        engine.key = key
        report = key_info.key_report(engine, 130, frozenset({hashlib.sha256(TEST_KEY_130).hexdigest()}))
        self.assertEqual(report["fingerprint"], hashlib.sha256(TEST_KEY_130).hexdigest())
        self.assertTrue(report["test_key"])
        self.assertEqual(held["key"], bytearray(32))  # wiped
        self.assertIsNone(key_info.key_report(engine, 9, None)["test_key"])  # no list: unknown, not "no"


class ProtocolTest(unittest.TestCase):
    def test_health_needs_no_session(self):
        sidecar = make_sidecar()
        self.assertEqual(sidecar.handle({"op": "health"}, sidecar.new_session()), {"op": "health", "ok": True})

    def test_verified_frame(self):
        client = Client(make_sidecar())
        status, spi, data, cryptolib_status, _ = client.process(frame(5, 7))
        self.assertEqual((status, spi, cryptolib_status), (wire.VERIFIED, 7, 0))
        self.assertEqual(len(data), 1786 - 6 - 2 - 2 - 16)

    def test_decrypted_and_clear(self):
        client = Client(make_sidecar())
        self.assertEqual(client.process(frame(4, 6))[0], wire.DECRYPTED)
        self.assertEqual(client.process(frame(1, 5))[0], wire.CLEAR)

    def test_cryptolib_failure(self):
        client = Client(make_sidecar())
        bad = bytearray(frame(5, 7))
        bad[1786 - 16 - 1] = 0xBA
        status, spi, data, cryptolib_status, detail = client.process(bytes(bad))
        self.assertEqual((status, spi, data, cryptolib_status), (wire.FAILED, 7, None, -1))
        self.assertIn("MAC_VALIDATION", detail)

    def test_precheck_keeps_frames_away_from_cryptolib(self):
        sidecar = make_sidecar()
        client = Client(sidecar)
        cases = {
            "unknown SPI": frame(5, 9),
            "SPI on the wrong VC (CryptoLib 1.4 picked the SA from the SPI alone)": frame(1, 7),
            "wrong spacecraft": frame(5, 7, scid=4),
            "short": frame(5, 7)[:100],
        }
        for name, data in cases.items():
            with self.subTest(name):
                self.assertEqual(client.process(data)[0], wire.REFUSED)
        self.assertEqual(sidecar.engine.calls, 0)

    def test_requests_must_be_authenticated(self):
        sidecar = make_sidecar()
        client = Client(sidecar)
        request = wire.sign(OTHER_KEY, client.session, "request", wire.tm_process_request(1, frame(5, 7)))
        with self.assertRaises(wire.SidecarProtocolError):
            sidecar.handle(request, client.state)
        self.assertEqual(sidecar.counts["auth_failures"], 1)
        unsigned = wire.info_request(2)
        with self.assertRaises(wire.SidecarProtocolError):
            sidecar.handle(unsigned, client.state)

    def test_nothing_before_hello(self):
        sidecar = make_sidecar()
        with self.assertRaises(wire.SidecarProtocolError):
            sidecar.handle({"op": "info", "id": 1, "mac": "00"}, sidecar.new_session())

    def test_request_ids_must_increase(self):
        sidecar = make_sidecar()
        client = Client(sidecar)
        request = wire.sign(KEY, client.session, "request", wire.info_request(5))
        sidecar.handle(request, client.state)
        with self.assertRaises(wire.SidecarProtocolError):
            sidecar.handle(request, client.state)  # replayed request

    def test_a_request_from_another_session_is_refused(self):
        sidecar = make_sidecar()
        first, second = Client(sidecar), Client(sidecar)
        request = wire.sign(KEY, first.session, "request", wire.info_request(1))
        with self.assertRaises(wire.SidecarProtocolError):
            sidecar.handle(request, second.state)

    def test_wrong_key_id_or_key(self):
        sidecar = make_sidecar()
        answer = sidecar.handle(wire.hello_request("other", wire.new_nonce()), sidecar.new_session())
        self.assertFalse(answer["ok"])
        with self.assertRaises(wire.SidecarProtocolError):
            Client(sidecar, key=OTHER_KEY)  # the hello answer does not verify

    def test_info_reports_sas_keys_and_mask(self):
        import hashlib

        known = frozenset({hashlib.sha256(TEST_KEY_130).hexdigest()})
        info = Client(make_sidecar(known)).info()
        sa = info["security_associations"]["7"]
        self.assertEqual((sa["vcid"], sa["service"], sa["sn_len"], sa["mac_len"]), (5, "auth", 2, 16))
        self.assertTrue(sa["keys"]["authentication"]["test_key"])
        self.assertEqual(sa["mask"]["data_field"], False)
        self.assertNotIn("encryption", sa["keys"])
        self.assertEqual(info["security_associations"]["6"]["keys"]["encryption"]["id"], 9)
        self.assertNotIn("key", json.dumps(info).lower().replace("keys", "").replace("key_source", "")
                         .replace("test_key", "").replace("known_test_", ""))


class ChannelKeyTest(unittest.TestCase):
    def test_from_env(self):
        keys = channel_keys_from_env({"EAGLEGATE_SIDECAR_KEY_FILE": "", "EAGLEGATE_SIDECAR_KEY": KEY.hex(),
                                      "EAGLEGATE_SIDECAR_KEY_ID": "k2"})
        self.assertEqual(keys, {"k2": KEY})
        self.assertEqual(channel_keys_from_env({"EAGLEGATE_SIDECAR_KEY_FILE": ""}), {})
        with self.assertRaises(ValueError):
            channel_keys_from_env({"EAGLEGATE_SIDECAR_KEY_FILE": "", "EAGLEGATE_SIDECAR_KEY": "abcd"})

    def test_no_key_no_sidecar(self):
        config = nos3_config()
        with self.assertRaises(ValueError):
            Sidecar(config, FakeEngine(config), {})


if __name__ == "__main__":
    unittest.main()
