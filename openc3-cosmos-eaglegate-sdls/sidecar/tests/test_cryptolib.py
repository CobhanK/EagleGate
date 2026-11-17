"""The real CryptoLib (test image only; skipped elsewhere).

Frames are protected with CryptoLib's own Crypto_TM_ApplySecurity (what the
spacecraft runs, through the test-only shim eg_test_apply.c) and checked with
the sidecar's engine, so every expectation comes from CryptoLib itself.
"""
import ctypes
import hashlib
import json
import os
import unittest

from tests import _paths  # noqa: F401  (sys.path)

import eaglegate_sdls_sidecar_protocol as wire
from eaglegate_sidecar import config as cfg
from eaglegate_sidecar import keys as key_info

LIB_DIR = "/opt/eaglegate/lib"
HAVE_CRYPTOLIB = os.path.exists(os.path.join(LIB_DIR, "libeg_test_apply.so"))
LENGTH = 1786
SLACK = 64


def header(vcid, scid=3, vc_count=0):
    data = bytearray(LENGTH)
    data[0] = (scid >> 4) & 0x3F
    data[1] = ((scid & 0x0F) << 4) | (vcid << 1)
    data[3] = vc_count & 0xFF
    data[4], data[5] = 0x18, 0x00  # packet mode, first header pointer 0
    return data


@unittest.skipUnless(HAVE_CRYPTOLIB, "needs the sidecar test image (CryptoLib)")
class CryptoLibCase(unittest.TestCase):
    """One CryptoLib per process: each class sets it up and shuts it down."""

    CONFIG = None  # dict; None = config/nos3.json
    CUSTOM_KEYS = None  # [(id, bytes, state)] for key_source "custom"

    @classmethod
    def setUpClass(cls):
        from eaglegate_sidecar.engine import CryptoLibEngine

        cls.config = cfg.parse(cls.CONFIG) if cls.CONFIG else cfg.load(_paths.NOS3_CONFIG)
        keys = [(k, bytearray(v), s) for k, v, s in (cls.CUSTOM_KEYS or [])]
        cls.engine = CryptoLibEngine(cls.config, custom_keys=keys)
        cls.apply_lib = ctypes.CDLL(os.path.join(LIB_DIR, "libeg_test_apply.so"))
        cls.apply_lib.eg_test_tm_apply.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_int]
        cls.apply_lib.eg_test_tm_apply.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.engine.close()

    def protect(self, spi, payload, vc_count=0):
        """A frame of SA `spi` carrying payload, protected by CryptoLib."""
        sa = self.config.sas[spi]
        data = header(sa.vcid, vc_count=vc_count)
        start = 6 + sa.header_length()
        end = LENGTH - sa.mac_len
        data[start:end] = (payload * (LENGTH // len(payload) + 1))[:end - start]
        # CryptoLib 1.5.1's ApplySecurity (the flight side) writes the whole
        # HMAC output (32 bytes for SHA-256) where the frame has room for
        # mac_len (16): with the MAC at the end of the frame that is 16 bytes
        # past it (found with valgrind). Give it slack; the sidecar never applies.
        slack = bytearray(data) + bytearray(SLACK)
        buffer = (ctypes.c_uint8 * len(slack)).from_buffer(slack)
        status = self.apply_lib.eg_test_tm_apply(buffer, LENGTH)
        self.assertEqual(status, 0, self.engine.status_name(status))
        data = slack[:LENGTH]
        return bytes(data), bytes(data[start:end]) if sa.service != "enc" else None

    def plaintext(self, spi, payload):
        sa = self.config.sas[spi]
        size = LENGTH - 6 - sa.header_length() - sa.mac_len
        return (payload * (size // len(payload) + 1))[:size]


class Nos3SasTest(CryptoLibCase):
    def test_cryptolib_holds_the_configured_sas(self):
        held = self.engine.sa_settings(7)
        self.assertEqual((held["state"], held["vcid"], held["ast"], held["acs"], held["akid"], held["shsnf_len"],
                          held["stmacf_len"]), (3, 5, 1, cfg.ACS["HMAC_SHA256"], 130, 2, 16))
        self.assertEqual(self.engine.sa_settings(1)["state"], 0)  # CryptoLib's built-in SAs are off

    def test_authenticated_frame_verifies_and_returns_the_data(self):
        frame, plain = self.protect(7, b"telemetry ")
        status, spi, data = self.engine.process(frame)
        self.assertEqual((status, spi), (0, 7))
        self.assertEqual(data, plain)

    def test_checks_are_pure_the_same_frame_verifies_twice(self):
        # CryptoLib's own TM anti-replay is off (EagleGate does anti-replay), so
        # processing changes no SA state
        frame, _ = self.protect(7, b"again ")
        self.assertEqual(self.engine.process(frame)[0], 0)
        self.assertEqual(self.engine.process(frame)[0], 0)

    def test_finding_nos3_zero_mask_mac_covers_nothing(self):
        """NOS3's SPI 7 has abm_len 1786 but an all-zero mask, and CryptoLib
        MACs only (frame AND mask) for authentication-only SAs: the MAC is the
        same for every frame, so a changed data field or sequence number still
        verifies. The sidecar reports this (mask.data_field false) and
        EagleGate does not count such frames as authenticated."""
        frame_a, _ = self.protect(7, b"first frame ")
        frame_b, _ = self.protect(7, b"something else entirely ")
        mac_a, mac_b = frame_a[-16:], frame_b[-16:]
        self.assertEqual(mac_a, mac_b)  # constant MAC
        tampered = bytearray(frame_a)
        tampered[20] ^= 0xFF          # data field
        tampered[8:10] = b"\x7f\xff"  # sequence number
        status, spi, data = self.engine.process(bytes(tampered))
        self.assertEqual(status, 0)   # still "verified" by CryptoLib
        coverage = key_info.mask_coverage(self.config.sas[7], self.config.tm)
        self.assertFalse(coverage["data_field"])
        self.assertFalse(coverage["sequence_number"])

    def test_encrypted_frame_decrypts_to_the_plaintext(self):
        frame, _ = self.protect(6, b"secret telemetry ")
        plain = self.plaintext(6, b"secret telemetry ")
        sa = self.config.sas[6]
        self.assertNotEqual(frame[6 + sa.header_length():], plain)  # encrypted on the wire
        status, spi, data = self.engine.process(frame)
        self.assertEqual((status, spi), (0, 6))
        self.assertEqual(data, plain)

    def test_clear_frame(self):
        frame, plain = self.protect(5, b"clear ")
        status, spi, data = self.engine.process(frame)
        self.assertEqual((status, spi, data), (0, 5, plain))

    def test_cryptolib_rejects_an_spi_on_another_vc(self):
        frame, _ = self.protect(7, b"x")
        moved = bytearray(frame)
        moved[1] = (moved[1] & 0xF1) | (1 << 1)  # VC 1
        self.assertNotEqual(self.engine.process(bytes(moved))[0], 0)

    def test_test_keys_are_recognized(self):
        known = key_info.load_known()
        self.assertIsNotNone(known)
        report = key_info.key_report(self.engine, 130, known)
        self.assertEqual((report["state"], report["length"], report["test_key"]), ("active", 32, True))
        self.assertEqual(len(report["fingerprint"]), 64)


class MutationTest(CryptoLibCase):
    """Damaged and random frames through CryptoLib's process path (what an
    attacker on the link controls): never a crash, never a false success for
    an SA whose mask covers the frame. Run under valgrind too (README)."""

    CONFIG = {"tm": {"scid": 3, "frame_length": LENGTH}, "security_associations": {
        "5": {"vcid": 1, "service": "clear", "iv_len": 12},
        "6": {"vcid": 4, "service": "authenc", "ecs": "AES256_GCM", "ekid": 9, "iv_len": 12, "sn_len": 2,
              "mac_len": 16, "abm": "ones"},
        "7": {"vcid": 5, "service": "auth", "acs": "HMAC_SHA256", "akid": 130, "sn_len": 2, "mac_len": 16,
              "abm": "ones"}}}

    def test_mutations(self):
        import random

        rng = random.Random(1)
        for spi in (6, 7):
            frame, plain = self.protect(spi, b"mutation ")
            status, _, data = self.engine.process(frame)
            self.assertEqual(status, 0)
            for _ in range(150):
                damaged = bytearray(frame)
                for _ in range(rng.randint(1, 4)):
                    damaged[rng.randrange(6, LENGTH)] ^= 1 << rng.randrange(8)
                if damaged == frame:
                    continue
                status, _, data = self.engine.process(bytes(damaged))
                self.assertNotEqual(status, 0)
        for _ in range(100):
            junk = bytes(rng.randrange(256) for _ in range(rng.choice((1, 6, 8, 100, LENGTH - 1, LENGTH))))
            self.engine.process(junk)  # must return, whatever it says


class FullMaskTest(CryptoLibCase):
    """The same SA with a mask over the whole frame: now CryptoLib's MAC
    covers the header and data, and any change fails."""

    CONFIG = {"tm": {"scid": 3, "frame_length": LENGTH}, "security_associations": {"7": {
        "vcid": 5, "service": "auth", "acs": "HMAC_SHA256", "akid": 130, "sn_len": 2, "mac_len": 16,
        "abm": "ones"}}}

    def test_any_change_fails(self):
        frame, plain = self.protect(7, b"protected ")
        status, _, data = self.engine.process(frame)
        self.assertEqual((status, data), (0, plain))
        for where in (3, 8, 9, 20, LENGTH - 17):  # VC count, sequence number, data
            tampered = bytearray(frame)
            tampered[where] ^= 0x01
            with self.subTest(byte=where):
                status, _, data = self.engine.process(bytes(tampered))
                self.assertNotEqual(status, 0)
                self.assertIsNone(data)

    def test_mac_differs_per_frame(self):
        a, _ = self.protect(7, b"one ")
        b, _ = self.protect(7, b"two ")
        self.assertNotEqual(a[-16:], b[-16:])


AUTH_KEY = bytes(range(100, 132))     # not one of CryptoLib's test keys
ENC_KEY = bytes(range(200, 232))
CUSTOM_SAS = {
    "6": {"vcid": 4, "service": "enc", "ecs": "AES256_GCM", "ekid": 9, "iv_len": 12, "abm": "zeros"},
    "7": {"vcid": 5, "service": "auth", "acs": "HMAC_SHA256", "akid": 130, "sn_len": 2, "mac_len": 16,
          "abm": "ones"}}


class CustomKeysTest(CryptoLibCase):
    """key_source "custom" (decision D12): CryptoLib's custom key interface,
    filled by the sidecar. CryptoLib protects (flight side) and checks with
    whatever the ring holds, so every result is CryptoLib's own."""

    CONFIG = {"tm": {"scid": 3, "frame_length": LENGTH}, "key_source": "custom",
              "security_associations": CUSTOM_SAS}
    CUSTOM_KEYS = [(130, AUTH_KEY, 1), (9, ENC_KEY, 1)]

    def setUp(self):
        self.engine.load_keys([(130, bytearray(AUTH_KEY), 1), (9, bytearray(ENC_KEY), 1)])

    def test_custom_keys_verify_and_decrypt(self):
        frame, plain = self.protect(7, b"real key ")
        self.assertEqual(self.engine.process(frame), (0, 7, plain))
        frame, _ = self.protect(6, b"secret ")
        status, _, data = self.engine.process(frame)
        self.assertEqual((status, data), (0, self.plaintext(6, b"secret ")))

    def test_the_ring_holds_our_keys_and_no_test_keys(self):
        known = key_info.load_known()
        report = key_info.key_report(self.engine, 130, known)
        self.assertEqual((report["fingerprint"], report["state"], report["test_key"]),
                         (hashlib.sha256(AUTH_KEY).hexdigest(), "active", False))
        for key_id in (0, 1, 128, 131):  # ids where CryptoLib's internal ring has test keys
            self.assertEqual(key_info.key_report(self.engine, key_id, known)["length"], 0)

    def test_cryptolib_refuses_a_key_that_is_not_active(self):
        frame, _ = self.protect(7, b"before ")
        self.engine.load_keys([(130, bytearray(AUTH_KEY), 2), (9, bytearray(ENC_KEY), 1)])  # deactivated
        status, _, data = self.engine.process(frame)
        self.assertNotEqual(status, 0)
        self.assertIsNone(data)

    def test_after_a_reload_frames_need_the_new_key(self):
        old_frame, _ = self.protect(7, b"old key ")
        self.engine.load_keys([(130, bytearray(bytes(range(50, 82))), 1), (9, bytearray(ENC_KEY), 1)])
        self.assertNotEqual(self.engine.process(old_frame)[0], 0)
        new_frame, plain = self.protect(7, b"new key ")
        self.assertEqual(self.engine.process(new_frame), (0, 7, plain))

    def test_cryptolib_says_which_key_lengths_its_suites_need(self):
        self.assertEqual(self.engine.expected_key_length("ecs", cfg.ECS["AES256_GCM"]), 32)
        self.assertEqual(self.engine.expected_key_length("acs", cfg.ACS["HMAC_SHA256"]), 32)
        self.assertEqual(self.engine.expected_key_length("acs", cfg.ACS["HMAC_SHA512"]), 64)

    def test_the_ring_refuses_bad_entries(self):
        problems = self.engine.load_keys([(130, bytearray(AUTH_KEY), 9)])
        self.assertTrue(problems and "key 130" in problems[0])

    def test_the_sidecar_reports_problems_from_cryptolib(self):
        from eaglegate_sidecar import keystore
        from eaglegate_sidecar.server import Sidecar

        self.engine.load_keys([(130, bytearray(AUTH_KEY), 0), (9, bytearray(ENC_KEY[:16]), 1)])
        sidecar = Sidecar(self.config, self.engine, {"default": bytes(32)}, key_info.load_known(), "/k", [])
        problems = " | ".join(sidecar.info["key_problems"])
        self.assertIn("key 130 is preactive, not active", problems)
        self.assertIn("key 9 is 16 bytes; CryptoLib expects 32", problems)
        self.assertNotIn(AUTH_KEY.hex(), json.dumps(sidecar.info))
        self.assertIsNotNone(keystore)


@unittest.skipUnless(HAVE_CRYPTOLIB, "needs the sidecar test image (CryptoLib)")
class SidecarEndToEndTest(unittest.TestCase):
    """The protocol over the real engine (no sockets)."""

    def test_hello_info_process(self):
        from eaglegate_sidecar.engine import CryptoLibEngine
        from eaglegate_sidecar.server import Sidecar

        config = cfg.load(_paths.NOS3_CONFIG)
        engine = CryptoLibEngine(config)
        try:
            key = bytes(range(32))
            sidecar = Sidecar(config, engine, {"default": key}, key_info.load_known())
            state = sidecar.new_session()
            nonce = wire.new_nonce()
            session = wire.parse_hello_response(sidecar.handle(wire.hello_request("default", nonce), state),
                                                key, "default", nonce)
            info = sidecar.handle(wire.sign(key, session, "request", wire.info_request(1)), state)
            wire.check_response(info, key, session, "info", 1)
            self.assertEqual(info["cryptolib"], "1.5.1")
            self.assertTrue(info["security_associations"]["7"]["keys"]["authentication"]["test_key"])
            self.assertNotIn(bytes(range(32)).hex(), json.dumps(info))
            frame = bytearray(header(1))
            frame[6:8] = (5).to_bytes(2, "big")
            request = wire.sign(key, session, "request", wire.tm_process_request(2, bytes(frame)))
            answer = sidecar.handle(request, state)
            wire.check_response(answer, key, session, "tm_process", 2)
            self.assertEqual(wire.parse_tm_process_response(answer, 2, bytes(frame))[0], wire.CLEAR)
            self.assertEqual(hashlib.sha256(bytes(frame)).hexdigest(), answer["frame_sha256"])
        finally:
            engine.close()


if __name__ == "__main__":
    unittest.main()
