"""Docker HEALTHCHECK: the server answers "health" (no session, no key needed)."""
import socket
import sys

import eaglegate_sdls_sidecar_protocol as wire


def main(port=7710):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            sock.sendall(wire.encode({"op": "health"}))
            buffer = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    return 1
                buffer += chunk
                message, buffer = wire.decode(buffer)
                if message is not None:
                    return 0 if message.get("ok") is True else 1
    except (OSError, wire.SidecarProtocolError):
        return 1


if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]) if len(sys.argv) > 1 else 7710))
