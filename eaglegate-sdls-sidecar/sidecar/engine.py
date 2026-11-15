"""CryptoLib, through the flat C shim (shim/eg_cryptolib.c), via ctypes.

All cryptography is CryptoLib's. This module only configures it from the
sidecar's configuration, reads back what CryptoLib holds (to report and to
cross-check), and calls Crypto_TM_ProcessSecurity. CryptoLib keeps global
state and is not thread safe: every call goes through one lock.
"""
import ctypes
import os
import threading

from . import config as cfg

DEFAULT_LIBRARY = "/opt/eaglegate/lib/libeg_cryptolib.so"
SUCCESS = 0
SA_OPERATIONAL = 3
KEY_STATES = {0: "preactive", 1: "active", 2: "deactivated", 3: "destroyed", 4: "corrupted"}
KEY_BUFFER = 512  # CryptoLib's KEY_SIZE
PDU_BUFFER = 1786
SA_FIELDS = ("state", "tfvn", "scid", "vcid", "est", "ast", "ecs", "acs", "ekid", "akid", "shivf_len", "iv_len",
             "shsnf_len", "arsn_len", "shplf_len", "stmacf_len")


class EngineError(RuntimeError):
    pass


class CryptoLibEngine:
    """One CryptoLib instance in this process (CryptoLib allows only one)."""

    def __init__(self, sidecar_config, library=None):
        self.config = sidecar_config
        self.lock = threading.Lock()
        if not os.access(os.getcwd(), os.W_OK):
            # CryptoLib 1.5.1's Crypto_Init writes sa_save_file.bin into the
            # working directory (even with SA_FILE off) and crashes if it cannot
            raise EngineError(f"the working directory {os.getcwd()} must be writable (CryptoLib writes "
                              "sa_save_file.bin there at start); run in a scratch directory or tmpfs")
        self.lib = ctypes.CDLL(library or os.environ.get("EG_CRYPTOLIB_SHIM", DEFAULT_LIBRARY))
        self._declare()
        version = self.lib.eg_cryptolib_version()
        self.version = f"{version // 10000}.{version // 100 % 100}.{version % 100}"
        if self.lib.eg_num_sa() < cfg.NUM_SA or self.lib.eg_num_keys() < cfg.NUM_KEYS:
            raise EngineError("CryptoLib was built with fewer SAs or keys than the sidecar expects")
        if self.lib.eg_abm_size() < sidecar_config.tm.frame_length:
            raise EngineError("CryptoLib's ABM_SIZE is smaller than the frame length")
        self._setup()

    def _declare(self):
        lib = self.lib
        c_int, c_int_p, u8_p = ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_uint8)
        lib.eg_cryptolib_version.restype = c_int
        lib.eg_num_sa.restype = c_int
        lib.eg_num_keys.restype = c_int
        lib.eg_abm_size.restype = c_int
        lib.eg_configure.argtypes = [c_int]
        lib.eg_add_tm_channel.argtypes = [c_int] * 6
        lib.eg_set_sa.argtypes = [c_int] * 16 + [u8_p, c_int]
        lib.eg_get_sa.argtypes = [ctypes.POINTER(ctypes.c_int32), u8_p, c_int, c_int_p]
        lib.eg_get_sa.argtypes = [c_int] + lib.eg_get_sa.argtypes
        lib.eg_get_key.argtypes = [c_int, u8_p, c_int, c_int_p, c_int_p]
        lib.eg_tm_process.argtypes = [u8_p, c_int, u8_p, c_int, c_int_p, c_int_p]
        lib.eg_status_name.argtypes = [c_int]
        lib.eg_status_name.restype = ctypes.c_char_p
        for name in ("eg_configure", "eg_add_tm_channel", "eg_init", "eg_shutdown", "eg_disable_all_sas",
                     "eg_set_sa", "eg_get_sa", "eg_get_key", "eg_tm_process"):
            getattr(lib, name).restype = c_int

    def _check(self, status, what):
        if status != SUCCESS:
            raise EngineError(f"{what}: {self.status_name(status)} ({status})")

    def _setup(self):
        tm = self.config.tm
        with self.lock:
            self._check(self.lib.eg_configure(int(tm.has_fecf)), "Crypto_Config")
            for vcid in self.config.channels:
                self._check(self.lib.eg_add_tm_channel(tm.tfvn, tm.scid, vcid, int(tm.has_fecf), tm.frame_length,
                                                       int(tm.has_ocf)), f"managed parameters for VC {vcid}")
            self._check(self.lib.eg_init(), "Crypto_Init")
            self._check(self.lib.eg_disable_all_sas(), "disabling the built-in SAs")
            for sa in self.config.sas.values():
                abm = (ctypes.c_uint8 * max(1, len(sa.abm))).from_buffer_copy(sa.abm or b"\0")
                self._check(self.lib.eg_set_sa(
                    sa.spi, tm.tfvn, tm.scid, sa.vcid, int(sa.est), int(sa.ast), cfg.ECS[sa.ecs], cfg.ACS[sa.acs],
                    sa.ekid, sa.akid, sa.iv_len, sa.iv_total_len, sa.sn_len, sa.arsn_len, sa.pl_len, sa.mac_len,
                    abm, len(sa.abm)), f"SA {sa.spi}")
        # Read every SA back: what CryptoLib holds must be what was configured
        for sa in self.config.sas.values():
            held = self.sa_settings(sa.spi)
            expected = {"state": SA_OPERATIONAL, "tfvn": tm.tfvn, "scid": tm.scid, "vcid": sa.vcid,
                        "est": int(sa.est), "ast": int(sa.ast), "ecs": cfg.ECS[sa.ecs], "acs": cfg.ACS[sa.acs],
                        "ekid": sa.ekid, "akid": sa.akid, "shivf_len": sa.iv_len, "iv_len": sa.iv_total_len,
                        "shsnf_len": sa.sn_len, "arsn_len": sa.arsn_len, "shplf_len": sa.pl_len,
                        "stmacf_len": sa.mac_len, "abm": sa.abm}
            different = sorted(k for k, v in expected.items() if held.get(k) != v)
            if different:
                raise EngineError(f"CryptoLib holds different settings for SA {sa.spi}: {different}")

    def close(self):
        """Crypto_Shutdown: free CryptoLib's state (a new engine may follow)."""
        with self.lock:
            self.lib.eg_shutdown()

    def status_name(self, status):
        name = self.lib.eg_status_name(status)
        return name.decode("ascii", "replace") if name else str(status)

    def sa_settings(self, spi):
        out = (ctypes.c_int32 * len(SA_FIELDS))()
        abm = (ctypes.c_uint8 * cfg.MAX_FRAME)()
        abm_len = ctypes.c_int()
        with self.lock:
            self._check(self.lib.eg_get_sa(spi, out, abm, cfg.MAX_FRAME, ctypes.byref(abm_len)), f"reading SA {spi}")
        settings = dict(zip(SA_FIELDS, list(out), strict=True))
        settings["abm"] = bytes(abm[:abm_len.value])
        return settings

    def key(self, key_id):
        """(bytearray of the key, state name). The caller wipes the bytearray."""
        buffer = (ctypes.c_uint8 * KEY_BUFFER)()
        length, state = ctypes.c_int(), ctypes.c_int()
        try:
            with self.lock:
                status = self.lib.eg_get_key(key_id, buffer, KEY_BUFFER, ctypes.byref(length), ctypes.byref(state))
            self._check(status, f"key {key_id}")
            return bytearray(buffer[:length.value]), KEY_STATES.get(state.value, f"state {state.value}")
        finally:
            ctypes.memset(buffer, 0, KEY_BUFFER)

    def process(self, frame):
        """CryptoLib's verdict on one TM frame: (status, spi or None, data field or None)."""
        source = (ctypes.c_uint8 * len(frame)).from_buffer_copy(frame)
        out = (ctypes.c_uint8 * PDU_BUFFER)()
        out_len, spi = ctypes.c_int(), ctypes.c_int()
        try:
            with self.lock:
                status = self.lib.eg_tm_process(source, len(frame), out, PDU_BUFFER, ctypes.byref(out_len),
                                                ctypes.byref(spi))
            data = bytes(out[:out_len.value]) if status == SUCCESS else None
            return status, (spi.value if spi.value >= 0 else None), data
        finally:
            ctypes.memset(out, 0, PDU_BUFFER)
