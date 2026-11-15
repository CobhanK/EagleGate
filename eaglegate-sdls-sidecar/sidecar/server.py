"""The sidecar's TCP server: answers EagleGate's wire protocol v1
(eaglegate_sdls_sidecar_protocol.py, copied into the image) with CryptoLib.

  python -m sidecar.server --config /etc/eaglegate-sidecar/sidecar.json [--port 7710]

Environment:
  EAGLEGATE_SIDECAR_KEY_FILE  file holding the channel key as hex (a docker
                              secret; default /run/secrets/eaglegate_sidecar_key)
  EAGLEGATE_SIDECAR_KEY       the key itself, when there is no file (tests)
  EAGLEGATE_SIDECAR_KEY_ID    its key id (default "default")

Before CryptoLib sees a frame the sidecar checks its length, version,
spacecraft ID, virtual channel and SPI against its own configuration, so
CryptoLib only parses frames of the SAs configured here, on their own VC.
Nothing is logged about frame contents or keys.
"""
import argparse
import os
import socket
import socketserver
import sys
import threading
import time

import eaglegate_sdls_sidecar_protocol as wire

from . import config as cfg
from . import keys as key_info

SIDECAR_VERSION = "0.2.0"
DEFAULT_PORT = 7710
DEFAULT_KEY_FILE = "/run/secrets/eaglegate_sidecar_key"
MAX_CONNECTIONS = 16
IDLE_TIMEOUT = 3600.0


def log(text):
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} eaglegate-sdls-sidecar: {text}", flush=True)


class Sidecar:
    """The protocol logic, independent of sockets (tests drive it directly)."""

    def __init__(self, sidecar_config, engine, channel_keys, known_test_keys=None):
        if not channel_keys:
            raise ValueError("no channel key: set EAGLEGATE_SIDECAR_KEY_FILE (or EAGLEGATE_SIDECAR_KEY)")
        self.config = sidecar_config
        self.engine = engine
        self.channel_keys = dict(channel_keys)
        self.known = known_test_keys
        self.counts = dict.fromkeys(("requests", "verified", "decrypted", "clear", "failed", "refused",
                                     "auth_failures"), 0)
        self.count_lock = threading.Lock()
        self.info = self._info()

    def _info(self):
        sas = {}
        for spi, sa in sorted(self.config.sas.items()):
            keys = {}
            if sa.est:
                keys["encryption"] = key_info.key_report(self.engine, sa.ekid, self.known)
            if sa.ast:
                keys["authentication"] = key_info.key_report(self.engine, sa.akid, self.known)
            sas[str(spi)] = {
                "vcid": sa.vcid, "service": sa.service, "ecs": sa.ecs, "acs": sa.acs, "ekid": sa.ekid,
                "akid": sa.akid, "iv_len": sa.iv_len, "sn_len": sa.sn_len, "pl_len": sa.pl_len,
                "mac_len": sa.mac_len, "iv_total_len": sa.iv_total_len, "arsn_len": sa.arsn_len,
                "mask": key_info.mask_coverage(sa, self.config.tm), "keys": keys}
        tm = self.config.tm
        return {"sidecar": SIDECAR_VERSION, "cryptolib": self.engine.version, "key_source": self.config.key_source,
                "known_test_keys": self.known is not None,
                "tm": {"tfvn": tm.tfvn, "scid": tm.scid, "frame_length": tm.frame_length, "has_fecf": tm.has_fecf,
                       "has_ocf": tm.has_ocf, "secondary_header_length": tm.secondary_header_length},
                "security_associations": sas}

    def _count(self, name):
        with self.count_lock:
            self.counts[name] += 1

    # ---- one connection ------------------------------------------------------

    def new_session(self):
        return {"session": None, "key": None, "last_id": 0}

    def handle(self, message, state):
        """The answer to one message, or raises wire.SidecarProtocolError (the
        caller then closes the connection without answering)."""
        op = message.get("op")
        if op == "health":
            return {"op": "health", "ok": True}
        if op == "hello":
            return self._hello(message, state)
        if state["session"] is None:
            raise wire.SidecarProtocolError(f"{op!r} before hello")
        if not wire.verify(state["key"], state["session"], "request", message):
            self._count("auth_failures")
            raise wire.SidecarProtocolError("request failed authentication")
        request_id = message.get("id")
        if not isinstance(request_id, int) or isinstance(request_id, bool) or request_id <= state["last_id"]:
            raise wire.SidecarProtocolError("request ids must increase")
        state["last_id"] = request_id
        if op == "info":
            answer = {"op": "info", "id": request_id, "ok": True, **self.info, "counts": dict(self.counts)}
        elif op == "tm_process":
            answer = self._tm_process(message, request_id)
        else:
            raise wire.SidecarProtocolError(f"unknown op {op!r}")
        return wire.sign(state["key"], state["session"], "response", answer)

    def _hello(self, message, state):
        if state["session"] is not None:
            raise wire.SidecarProtocolError("hello twice")
        kid, client_nonce = message.get("kid"), message.get("client_nonce")
        key = self.channel_keys.get(kid) if isinstance(kid, str) else None
        if key is None:
            self._count("auth_failures")
            return {"op": "hello", "ok": False, "detail": "unknown key id"}
        if not isinstance(client_nonce, str) or len(wire.unb64(client_nonce, "client_nonce")) != wire.NONCE_BYTES:
            raise wire.SidecarProtocolError("hello needs a client nonce")
        server_nonce = wire.new_nonce()
        state.update(session=wire.session_id(client_nonce, server_nonce), key=key)
        return wire.hello_response(key, kid, client_nonce, server_nonce)

    def _tm_process(self, message, request_id):
        self._count("requests")
        frame = wire.unb64(message.get("frame"), "frame")
        spi, refusal = self.precheck(frame)
        if refusal:
            self._count("refused")
            return wire.tm_process_response(request_id, frame, wire.REFUSED, spi=spi, detail=refusal)
        sa = self.config.sas[spi]
        status, reported_spi, data = self.engine.process(frame)
        if status != 0:
            self._count("failed")
            return wire.tm_process_response(request_id, frame, wire.FAILED, spi=spi, cryptolib_status=status,
                                            detail=f"CryptoLib: {self.engine.status_name(status)}")
        if reported_spi != spi:
            self._count("failed")
            return wire.tm_process_response(request_id, frame, wire.FAILED, spi=spi, cryptolib_status=status,
                                            detail=f"CryptoLib read SPI {reported_spi}, expected {spi}")
        result = {"clear": wire.CLEAR, "auth": wire.VERIFIED}.get(sa.service, wire.DECRYPTED)
        self._count(result)
        return wire.tm_process_response(request_id, frame, result, spi=spi, data_field=data, cryptolib_status=0)

    def precheck(self, frame):
        """(spi, None) when CryptoLib may see the frame, else (spi or None, why not)."""
        tm = self.config.tm
        if len(frame) != tm.frame_length:
            return None, f"frame is {len(frame)} bytes, expected {tm.frame_length}"
        version = frame[0] >> 6
        scid = ((frame[0] & 0x3F) << 4) | (frame[1] >> 4)
        vcid = (frame[1] >> 1) & 0x07
        if version != tm.tfvn or scid != tm.scid:
            return None, f"version {version} / spacecraft ID {scid}, expected {tm.tfvn} / {tm.scid}"
        offset = tm.spi_offset
        spi = int.from_bytes(frame[offset:offset + cfg.SPI_LEN], "big")
        sa = self.config.sas.get(spi)
        if sa is None:
            return spi, f"SPI {spi} is not configured in the sidecar"
        if sa.vcid != vcid:
            return spi, f"SPI {spi} is bound to VC {sa.vcid}, the frame is on VC {vcid}"
        return spi, None


# ---- sockets -----------------------------------------------------------------

class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        if not server.slots.acquire(blocking=False):
            return  # too many connections: close
        with server.open_lock:
            server.open.add(self.request)
        try:
            self._serve(server.sidecar)
        finally:
            with server.open_lock:
                server.open.discard(self.request)
            server.slots.release()

    def _serve(self, sidecar):
        sock = self.request
        sock.settimeout(IDLE_TIMEOUT)
        state = sidecar.new_session()
        buffer = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except (TimeoutError, socket.timeout, OSError):
                return
            if not chunk:
                return
            buffer += chunk
            while True:
                try:
                    message, buffer = wire.decode(buffer)
                    if message is None:
                        break
                    answer = sidecar.handle(message, state)
                except wire.SidecarProtocolError as error:
                    log(f"closing a connection from {self.client_address[0]}: {error}")
                    return
                try:
                    sock.sendall(wire.encode(answer))
                except OSError:
                    return


class SidecarServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, sidecar):
        self.sidecar = sidecar
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.open = set()
        self.open_lock = threading.Lock()
        super().__init__(address, _Handler)

    def close_connections(self):
        """Drop every open connection (shutdown only stops accepting new ones)."""
        with self.open_lock:
            for sock in list(self.open):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


def channel_keys_from_env(env=None):
    env = os.environ if env is None else env
    kid = env.get("EAGLEGATE_SIDECAR_KEY_ID", "default")
    path = env.get("EAGLEGATE_SIDECAR_KEY_FILE", DEFAULT_KEY_FILE)
    text = None
    if path and os.path.exists(path):
        with open(path, encoding="ascii") as handle:
            text = handle.read()
    elif env.get("EAGLEGATE_SIDECAR_KEY"):
        text = env["EAGLEGATE_SIDECAR_KEY"]
    return {kid: wire.parse_key(text)} if text else {}


def main(argv=None):
    parser = argparse.ArgumentParser(description="EagleGate SDLS sidecar (NASA CryptoLib)")
    parser.add_argument("--config", default="/etc/eaglegate-sidecar/sidecar.json")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args(argv)
    from .engine import CryptoLibEngine

    try:
        sidecar_config = cfg.load(args.config)
        keys = channel_keys_from_env()
        engine = CryptoLibEngine(sidecar_config)
        sidecar = Sidecar(sidecar_config, engine, keys, key_info.load_known())
    except (cfg.ConfigError, ValueError, OSError, RuntimeError) as error:
        log(f"cannot start: {error}")
        return 1
    test = [spi for spi, sa in sidecar.info["security_associations"].items()
            if any(k.get("test_key") for k in sa["keys"].values())]
    log(f"CryptoLib {engine.version}, SAs {sorted(sidecar_config.sas)}, key source {sidecar_config.key_source}"
        + (f"; TEST KEYS on SPI {', '.join(test)} (never use in operations)" if test else ""))
    with SidecarServer((args.host, args.port), sidecar) as server:
        log(f"listening on {args.host}:{args.port}")
        server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
