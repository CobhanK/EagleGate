"""SidecarCrypto: frames verified and decrypted by NASA CryptoLib in the
eaglegate-sdls-sidecar container (link.crypto.backend "sidecar").

EagleGate never holds SDLS keys. It sends each frame of an authenticating or
encrypting SA to the sidecar over the authenticated wire protocol
(eaglegate_sdls_sidecar_protocol.py, HMAC-SHA256 with the channel key from the
COSMOS secret EAGLEGATE_SIDECAR_KEY) and turns the answer into a SecurityResult.
Clear SAs are not sent: there is nothing to check.

Fail closed, with the admin's choice (link.crypto.on_unavailable):
  * sidecar unreachable, slow, or answering garbage: UNAVAILABLE (rejected,
    never decides trust), or with "unverified" as if there were no backend
  * its SA table differs from the rules' security_associations (mode, field
    lengths, VC binding, the ekid/akid the rules name): REFUSED for every
    frame of that SA until it matches
  * CryptoLib refuses a frame (bad MAC, decryption error): FAILED

What a "verified" answer is worth depends on the SA's authentication bit mask,
which the sidecar reports: CryptoLib MACs only (frame AND mask), so a mask that
leaves the data field out authenticates nothing EagleGate passes on. Such
frames stay auth_unverified, and the anti-replay counter counts as
authenticated only when the mask covers it.

Key management: each SA's key epoch is the SHA-256 fingerprints of its keys as
the sidecar reports them. A new epoch (a new key) starts a new anti-replay
baseline (eaglegate_sdls_replay.py), and CryptoLib's published test keys are
recognized (link.crypto.test_keys: warn or deny).
"""
import os
import socket
import time

import eaglegate_sdls_sidecar_protocol as wire
from eaglegate_sdls_frame_security import (CLEAR, DECRYPTED, FAILED, REFUSED, UNAVAILABLE, UNREADABLE, UNVERIFIED,
                                           VERIFIED, FrameSecurity, SecurityResult)

KEY_ENV = "EAGLEGATE_SIDECAR_KEY"
MAX_BACKOFF = 30.0
INFO_REFRESH = 60.0  # seconds between re-reading the sidecar's SA table and keys
RELOAD_TIMEOUT = 10.0  # seconds a key reload may take (reads the secret, fingerprints keys)
EPOCH_CHARS = 16     # fingerprint characters in a key epoch


class SidecarCrypto(FrameSecurity):
    name = "sidecar"

    def __init__(self, crypto, link=None, interface_name="?", env=None, connector=None, clock=time.monotonic):
        self.crypto = crypto
        self.link = link
        self.interface_name = interface_name
        self.clock = clock
        self.connector = connector or self._connect_socket
        self.key = None
        self.key_problem = None
        env = os.environ if env is None else env
        try:
            self.key = wire.parse_key(env.get(KEY_ENV, ""))
        except ValueError as error:
            self.key_problem = (f"{error} (set the COSMOS secret {KEY_ENV} for this interface, see the SDLS "
                                "plugin's plugin.txt)")
        self.sock = None
        self.buffer = b""
        self.session = None
        self.next_id = 1
        self.info = None
        self.info_at = None
        self.info_stale = False   # set by reload_keys (command thread): re-read info before the next frame
        self.mismatch = {}        # spi -> why the sidecar's SA differs from the rules
        self.down_until = 0.0
        self.backoff = 1.0
        self.last_error = None
        self.latency_ms = None
        self.max_latency_ms = 0.0
        self.counts = dict.fromkeys(("frames", "verified", "decrypted", "failed", "refused", "unavailable",
                                     "timeouts", "connects", "mask_unverified", "test_key_denied"), 0)

    # ---- FrameSecurity ---------------------------------------------------------

    def configure(self, link):
        """The rules' link section changed: compare the SA table again."""
        self.link = link
        if self.info is not None:
            self.mismatch = self._compare(self.info)

    def process(self, frame, sa):
        if not sa.authenticated and not sa.encrypted:
            return SecurityResult(CLEAR, protection="clear", data_field=frame.data_field)
        self.counts["frames"] += 1
        if self.key is None:
            return self._unavailable(sa, self.key_problem)
        if not self._ready():
            return self._unavailable(sa, self.last_error or "not connected")
        if sa.spi in self.mismatch:
            self.counts["refused"] += 1
            return SecurityResult(REFUSED, detail=f"the sidecar's SA {sa.spi} does not match the rules: "
                                                  f"{self.mismatch[sa.spi]}")
        report = self.info["security_associations"][str(sa.spi)]
        if self.crypto.test_keys == "deny" and _uses_test_key(report):
            self.counts["test_key_denied"] += 1
            return SecurityResult(REFUSED, detail=f"SPI {sa.spi} uses one of CryptoLib's published test keys and "
                                                  "link.crypto.test_keys is deny")
        try:
            answer = self._call(wire.tm_process_request, frame.raw)
            status, spi, data, cryptolib_status, detail = wire.parse_tm_process_response(
                answer, answer.get("id"), frame.raw)
        except (OSError, wire.SidecarProtocolError) as error:
            self._lost(error)
            return self._unavailable(sa, self.last_error)
        return self._result(frame, sa, report, status, spi, data, cryptolib_status, detail)

    def _result(self, frame, sa, report, status, spi, data, cryptolib_status, detail):
        if status == wire.FAILED:
            self.counts["failed"] += 1
            return SecurityResult(FAILED, detail=f"CryptoLib refused the frame: {detail or cryptolib_status}")
        if status == wire.REFUSED:
            self.counts["refused"] += 1
            return SecurityResult(REFUSED, detail=f"the sidecar refused the frame: {detail}")
        expected = {"auth": wire.VERIFIED, "enc": wire.DECRYPTED, "authenc": wire.DECRYPTED}[sa.mode]
        if status != expected or spi != sa.spi:
            self.counts["failed"] += 1
            return SecurityResult(FAILED, detail=f"the sidecar answered {status} for SPI {spi}; SPI {sa.spi} "
                                                 f"({sa.mode}) must be {expected}")
        usable = len(frame.data_field) - frame.pad_length
        if len(data) != usable:
            self.counts["failed"] += 1
            return SecurityResult(FAILED, detail=f"the sidecar returned {len(data)} data bytes, the frame has "
                                                 f"{usable}")
        if sa.mode == "auth" and data != frame.data_field[:usable]:
            self.counts["failed"] += 1
            return SecurityResult(FAILED, detail="the sidecar returned other data than the frame carries")
        mask = report.get("mask") or {}
        epoch = self.key_epoch(sa.spi)
        if sa.mode == "auth" and not mask.get("data_field"):
            # CryptoLib "verified" a MAC that does not cover the data field
            self.counts["mask_unverified"] += 1
            return SecurityResult(UNVERIFIED, protection="auth_unverified", data_field=data, pad_removed=True,
                                  key_epoch=epoch, warnings=(_mask_warning(sa.spi, mask),))
        self.counts["verified" if status == wire.VERIFIED else "decrypted"] += 1
        counter = (sa.replay == "sn" and mask.get("sequence_number", False)) or \
            (sa.replay == "iv" and sa.mode == "authenc")  # GCM's tag covers its IV
        return SecurityResult(VERIFIED if status == wire.VERIFIED else DECRYPTED, protection=sa.mode,
                              data_field=data, pad_removed=True, key_epoch=epoch,
                              counter_verified=bool(counter and sa.authenticated))

    def _unavailable(self, sa, detail):
        self.counts["unavailable"] += 1
        if self.crypto.on_unavailable == "unverified":
            if sa.encrypted:
                return SecurityResult(UNREADABLE, detail=f"crypto backend unavailable ({detail}); SPI {sa.spi} "
                                                         "encrypts, so its frames cannot be read")
            return SecurityResult(UNVERIFIED, protection="auth_unverified", detail=detail)
        return SecurityResult(UNAVAILABLE, detail=detail)

    def key_epoch(self, spi):
        report = ((self.info or {}).get("security_associations") or {}).get(str(spi))
        if not report:
            return None
        parts = []
        for role, tag in (("encryption", "e"), ("authentication", "a")):
            key = (report.get("keys") or {}).get(role)
            if key:
                if not key.get("fingerprint"):
                    return None
                parts.append(f"{tag}{key.get('id')}:{key['fingerprint'][:EPOCH_CHARS]}")
        return "/".join(parts) or None

    def sa_keys(self):
        result = {}
        sas = (self.info or {}).get("security_associations") or {}
        for spi, report in sas.items():
            keys = report.get("keys") or {}
            mask = report.get("mask")
            result[spi] = {
                "ekid": keys["encryption"]["id"] if "encryption" in keys else None,
                "akid": keys["authentication"]["id"] if "authentication" in keys else None,
                "fingerprints": " ".join(f"{k['id']}:{(k.get('fingerprint') or '?')[:EPOCH_CHARS]}"
                                         for k in keys.values()),
                "key_state": ", ".join(sorted({str(k.get("state")) for k in keys.values()})) or None,
                "test_key": _uses_test_key(report),
                "mask_covers_data": None if mask is None else mask.get("data_field"),
                "mask_covers_counter": None if mask is None else mask.get("sequence_number"),
                "matches_rules": int(spi) not in self.mismatch,
            }
        return result

    def sa_table(self):
        return (self.info or {}).get("security_associations")

    def status(self):
        info = self.info or {}
        return {
            "backend": self.name, "host": self.crypto.host, "port": self.crypto.port,
            "connected": self.session is not None, "sidecar": info.get("sidecar"), "cryptolib": info.get("cryptolib"),
            "key_source": info.get("key_source"),
            "key_problems": "; ".join(info.get("key_problems") or []) or None,
            "key_reloads": info.get("key_reloads"),
            "sa_match": (not self.mismatch) if self.info else None,
            "mismatch": {str(k): v for k, v in sorted(self.mismatch.items())},
            "test_key_spis": sorted(int(s) for s, r in (info.get("security_associations") or {}).items()
                                    if _uses_test_key(r)),
            "latency_ms": self.latency_ms, "max_latency_ms": round(self.max_latency_ms, 1),
            "last_error": self.last_error or self.key_problem, "counts": dict(self.counts),
        }

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.session = None
        self.buffer = b""

    def reload_keys(self):
        """Ask the sidecar to re-read its key secret (decision D12). Runs on the
        interface's command thread, so it uses a connection and session of its
        own and never touches the read thread's socket. Returns (ok, detail,
        problems); afterwards the read thread re-reads info (new fingerprints,
        so EagleGate's key epochs start new anti-replay baselines)."""
        if self.key is None:
            return False, self.key_problem, []
        sock, buffer = None, b""

        def send(message):
            sock.sendall(wire.encode(message))

        def receive():
            nonlocal buffer
            while True:
                message, buffer = wire.decode(buffer)
                if message is not None:
                    return message
                chunk = sock.recv(65536)
                if not chunk:
                    raise OSError("the sidecar closed the connection")
                buffer += chunk

        try:
            sock = self.connector(self.crypto.host, self.crypto.port, RELOAD_TIMEOUT)
            nonce = wire.new_nonce()
            send(wire.hello_request(self.crypto.key_id, nonce))
            session = wire.parse_hello_response(receive(), self.key, self.crypto.key_id, nonce)
            send(wire.sign(self.key, session, "request", wire.reload_keys_request(1)))
            answer = receive()
            wire.check_response(answer, self.key, session, "reload_keys", 1)
            ok, _, problems, detail = wire.parse_reload_keys_response(answer)
        except (OSError, wire.SidecarProtocolError) as error:
            return False, f"no answer from the sidecar at {self.crypto.host}:{self.crypto.port}: {error}", []
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self.info_stale = True
        return ok, detail, problems

    # ---- connection ------------------------------------------------------------

    def _ready(self):
        now = self.clock()
        if self.session is not None:
            if self.info_stale or (self.info_at is not None and now - self.info_at > INFO_REFRESH):
                try:
                    self._load_info()
                except (OSError, wire.SidecarProtocolError) as error:
                    self._lost(error)
                    return False
            return True
        if now < self.down_until:
            return False
        try:
            self.sock = self.connector(self.crypto.host, self.crypto.port, self.crypto.timeout_ms / 1000.0)
            self.counts["connects"] += 1
            nonce = wire.new_nonce()
            self._send(wire.hello_request(self.crypto.key_id, nonce))
            self.session = wire.parse_hello_response(self._receive(), self.key, self.crypto.key_id, nonce)
            self.next_id = 1
            self._load_info()
        except (OSError, wire.SidecarProtocolError) as error:
            self._lost(error)
            return False
        self.backoff = 1.0
        self.last_error = None
        return True

    def _load_info(self):
        answer = self._call(lambda request_id: wire.info_request(request_id))
        if not isinstance(answer.get("security_associations"), dict):
            raise wire.SidecarProtocolError("info answer without security_associations")
        self.info = answer
        self.info_at = self.clock()
        self.info_stale = False
        self.mismatch = self._compare(answer)

    def _call(self, build, *args):
        request_id = self.next_id
        self.next_id += 1
        request = wire.sign(self.key, self.session, "request", build(request_id, *args))
        started = time.monotonic()
        self._send(request)
        answer = self._receive()
        wire.check_response(answer, self.key, self.session, request["op"], request_id)
        if request["op"] == "tm_process":
            self.latency_ms = round((time.monotonic() - started) * 1000.0, 2)
            self.max_latency_ms = max(self.max_latency_ms, self.latency_ms)
        return answer

    def _send(self, message):
        self.sock.sendall(wire.encode(message))

    def _receive(self):
        while True:
            message, self.buffer = wire.decode(self.buffer)
            if message is not None:
                return message
            try:
                chunk = self.sock.recv(65536)
            except (TimeoutError, socket.timeout):
                self.counts["timeouts"] += 1
                raise OSError(f"no answer within {self.crypto.timeout_ms} ms") from None
            if not chunk:
                raise OSError("the sidecar closed the connection")
            self.buffer += chunk

    def _lost(self, error):
        self.close()
        self.last_error = f"{self.crypto.host}:{self.crypto.port}: {error}"[:256]
        self.down_until = self.clock() + self.backoff
        self.backoff = min(self.backoff * 2, MAX_BACKOFF)

    @staticmethod
    def _connect_socket(host, port, timeout):
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    # ---- does the sidecar's SA table match the rules? --------------------------

    def _compare(self, info):
        mismatch = {}
        if self.link is None:
            return mismatch
        theirs = info.get("security_associations") or {}
        for spi, sa in sorted(self.link.sas.items()):
            if sa.mode == "clear":
                continue
            report = theirs.get(str(spi))
            if report is None:
                mismatch[spi] = "the sidecar has no such SA"
                continue
            problems = []
            if report.get("service") != sa.mode:
                problems.append(f"mode {report.get('service')} (rules: {sa.mode})")
            for name in ("iv_len", "sn_len", "pl_len", "mac_len"):
                if report.get(name) != getattr(sa, name):
                    problems.append(f"{name} {report.get(name)} (rules: {getattr(sa, name)})")
            channels = sorted(vcid for vcid, spis in self.link.vcs.items() if spi in spis)
            if channels and channels != [report.get("vcid")]:
                problems.append(f"bound to VC {report.get('vcid')} (rules allow it on VC "
                                f"{', '.join(map(str, channels))})")
            for name, role in (("ekid", "encryption"), ("akid", "authentication")):
                wanted = getattr(sa, name)
                held = ((report.get("keys") or {}).get(role) or {}).get("id")
                if wanted is not None and held != wanted:
                    problems.append(f"{name} {held} (rules: {wanted})")
            if problems:
                mismatch[spi] = "; ".join(problems)
        return mismatch


def _uses_test_key(report):
    return any(key.get("test_key") for key in (report.get("keys") or {}).values())


def _mask_warning(spi, mask):
    return (f"SPI {spi}: CryptoLib checked the MAC, but the SA's authentication bit mask does not cover the data "
            f"field (mask covers {int(100 * (mask.get('primary_header') or 0))}% of the primary header, "
            f"sequence number {'yes' if mask.get('sequence_number') else 'no'}), so the MAC authenticates "
            "nothing passed on; treated as auth_unverified")
