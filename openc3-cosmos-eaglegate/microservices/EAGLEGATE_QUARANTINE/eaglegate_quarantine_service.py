"""EagleGate quarantine review service: the HTTP side of the review tool.

COSMOS runs this as a plugin microservice (plugin.txt: MICROSERVICE
EAGLEGATE_QUARANTINE) and Traefik routes /eaglegate-quarantine/... to it. The
EagleGate page calls it with the user's own COSMOS token, the same
Authorization header every COSMOS API call carries.

  GET  /eaglegate-quarantine/health                     no login; says only that it is up
  GET  /eaglegate-quarantine/entries?interface=&stream=&limit=&stage=&rule_id=&apid=&review=&search=&before=
  GET  /eaglegate-quarantine/entry?interface=&stream=&id=
  GET  /eaglegate-quarantine/export?interface=&stream=&format=json|pcap&limit=&<the list filters>
  POST /eaglegate-quarantine/review   {"interface", "stream", "ids", "state", "note", "requested_by"}

An export is a file download (JSON with every field and the bytes as hex, or
pcap) of up to 10000 matching entries, and is written to the audit stream.

Releasing is NOT done here: it goes through the firewall (RELEASE, see
targets/EAGLEGATE/lib/eaglegate_release.py), which owns the interface.

Who may use it (decision C5 in EagleGate/DECISIONS.md): only admins. COSMOS's
Python authorize() is a no-op, so this service never decides that itself: it
forwards the caller's token to an admin-only COSMOS endpoint
(GET /openc3-api/secrets, which lists secret NAMES, never values, and changes
nothing) and lets the COSMOS server answer. 200 = admin; 401/403 are passed
back. A positive answer is cached for ADMIN_CACHE_SECONDS per token, keyed by
the token's sha256; tokens are never logged or stored.
In COSMOS Core every logged in user is an admin (R5 in DECISIONS.md).

Standard library only.
"""
import base64
import collections
import hashlib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import eaglegate_quarantine_review as review

ROUTE_PREFIX = "/eaglegate-quarantine"
DEFAULT_PORT = 7720
MAX_BODY = 64 * 1024
ADMIN_CACHE_SECONDS = 30
ADMIN_CACHE_SIZE = 256
COSMOS_TIMEOUT = 5.0


# A file answer (an export) instead of a JSON payload
Download = collections.namedtuple("Download", "body content_type filename")


class HttpError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def cosmos_api_url():
    host = os.environ.get("OPENC3_API_HOSTNAME") or "openc3-cosmos-cmd-tlm-api"
    port = os.environ.get("OPENC3_API_PORT") or "2901"
    return f"http://{host}:{port}"


def user_from_token(token):
    """The user name inside a COSMOS Enterprise token (a Keycloak JWT), or "".
    Read only AFTER the COSMOS server accepted the token, so its signature has
    been checked there; Core tokens are not JWTs and give ""."""
    parts = str(token).split(" ")[-1].split(".")
    if len(parts) != 3:
        return ""
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, UnicodeError):
        return ""
    if not isinstance(claims, dict):
        return ""
    return review.clean(claims.get("preferred_username") or claims.get("name") or "", review.USER_CHARS)


class AdminCheck:
    """Asks the COSMOS server whether a token belongs to an admin."""

    def __init__(self, base_url=None, opener=None, clock=time.monotonic):
        self.base_url = base_url or cosmos_api_url()
        self.opener = opener or urllib.request.urlopen
        self.clock = clock
        self.cache = {}  # sha256(scope, token) -> (expires, user)
        self.lock = threading.Lock()

    def require_admin(self, token, scope):
        """The user name ("" when unknown). Raises HttpError 401/403/502."""
        if not token:
            raise HttpError(401, "log in to COSMOS first (no Authorization header)")
        key = hashlib.sha256(f"{scope}\0{token}".encode("utf-8", "replace")).hexdigest()
        now = self.clock()
        with self.lock:
            cached = self.cache.get(key)
            if cached and cached[0] > now:
                return cached[1]
        url = f"{self.base_url}/openc3-api/secrets?scope={urllib.parse.quote(scope)}"
        request = urllib.request.Request(url, headers={"Authorization": token, "Accept": "application/json"})
        try:
            with self.opener(request, timeout=COSMOS_TIMEOUT) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
        except (urllib.error.URLError, OSError) as error:
            raise HttpError(502, f"could not ask COSMOS who you are: {error}") from None
        if status == 401:
            raise HttpError(401, "COSMOS did not accept your login; log in again")
        if status == 403:
            raise HttpError(403, "the quarantine is for admins only: you need the COSMOS admin role")
        if status != 200:
            raise HttpError(502, f"COSMOS answered HTTP {status} to the admin check")
        user = user_from_token(token)
        with self.lock:
            if len(self.cache) >= ADMIN_CACHE_SIZE:
                self.cache = {k: v for k, v in self.cache.items() if v[0] > now}
                if len(self.cache) >= ADMIN_CACHE_SIZE:
                    self.cache.clear()
            self.cache[key] = (now + ADMIN_CACHE_SECONDS, user)
        return user


def _cosmos_store():
    from openc3.utilities.store import Store

    return Store.instance()


class ReviewApp:
    """Routes one request. Separate from the HTTP server so tests can call it."""

    def __init__(self, admin_check=None, store=None, prefix=ROUTE_PREFIX):
        self.admin_check = admin_check or AdminCheck()
        self.store = store or _cosmos_store
        self.prefix = prefix.rstrip("/")

    def handle(self, method, raw_path, headers, body=b""):
        """(status, payload dict)."""
        try:
            return 200, self._route(method, raw_path, headers, body)
        except HttpError as error:
            return error.status, {"error": str(error)}
        except review.QueryError as error:
            return 400, {"error": str(error)}
        except Exception as error:  # never leak a traceback to the page
            print(f"eaglegate-quarantine: {type(error).__name__}: {error}", file=sys.stderr, flush=True)
            return 500, {"error": f"internal error ({type(error).__name__}); see the microservice log"}

    def _route(self, method, raw_path, headers, body):
        parsed = urllib.parse.urlsplit(raw_path)
        path = parsed.path
        if not path.startswith(self.prefix):
            raise HttpError(404, "not found")
        path = path[len(self.prefix):].rstrip("/") or "/"
        params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items()}
        if path == "/health" and method == "GET":
            return {"ok": True}
        routes = {("GET", "/entries"), ("GET", "/entry"), ("GET", "/export"), ("POST", "/review")}
        if (method, path) not in routes:
            if any(p == path for _, p in routes):
                raise HttpError(405, f"{method} is not allowed here")
            raise HttpError(404, "not found")

        scope = review.name_param(params.get("scope", ""), "scope")
        user = self.admin_check.require_admin(headers.get("Authorization"), scope)
        store = self.store()
        if method == "POST":
            data = self._json_body(headers, body)
            interface = review.name_param(data.get("interface", "") if isinstance(data, dict) else "", "interface")
            stream, ids, state, note, requested_by = review.review_body(data)
            k = review.keys(scope, interface)
            return review.set_review(store, k, interface, stream, ids, state, note, user, requested_by)

        interface = review.name_param(params.get("interface", ""), "interface")
        k = review.keys(scope, interface)
        if path == "/entries":
            result = review.list_entries(store, k, review.list_query(params))
            return {"interface": interface, **result}
        if path == "/export":
            return self._export(store, k, scope, interface, params, user)
        stream = review.stream_param(params.get("stream"))
        entry_id = review.entry_id_param(params.get("id", ""))
        entry = review.get_entry(store, k, stream, entry_id)
        if entry is None:
            raise HttpError(404, f"entry {entry_id} is not in the {stream} stream (it may have been trimmed)")
        return {"interface": interface, "entry": entry}

    @staticmethod
    def _export(store, k, scope, interface, params, user):
        query, fmt = review.export_query(params)
        result = review.export_entries(store, k, query)
        entries = result["entries"]
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        audit_id = review.audit_export(store, k, interface, query["stream"], fmt, len(entries), query, user)
        filename = f"eaglegate-{interface}-{query['stream']}-{stamp}.{fmt}"
        if fmt == "pcap":
            return Download(review.export_pcap(entries), "application/vnd.tcpdump.pcap", filename)
        meta = {"exported_at": review.utc_now(), "exported_by": user, "scope": scope, "interface": interface,
                "stream": query["stream"], "audit_id": audit_id,
                "filters": {key: value for key, value in query.items() if value not in ("", None)},
                "complete": result["next_before"] is None,
                "note": "packet bytes are hex; text fields are cleaned (control and invisible "
                        "characters escaped). Handle this file as sensitive."}
        return Download(review.export_json(entries, meta), "application/json", filename)

    @staticmethod
    def _json_body(headers, body):
        content_type = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type != "application/json":
            raise HttpError(415, "send the review as application/json")
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HttpError(400, "the request body is not valid JSON") from None


class Handler(BaseHTTPRequestHandler):
    server_version = "EagleGateQuarantine"
    sys_version = ""

    def do_GET(self):
        self._serve("GET", b"")

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_BODY:
            self._send(413, {"error": f"the request body must be at most {MAX_BODY} bytes"})
            return
        self._serve("POST", self.rfile.read(length))

    def _serve(self, method, body):
        status, payload = self.server.app.handle(method, self.path, self.headers, body)
        self._send(status, payload)

    def _send(self, status, payload):
        if isinstance(payload, Download):
            data, content_type = payload.body, payload.content_type
        else:
            data = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")
            content_type = "application/json; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if isinstance(payload, Download):
            # The name is built from checked parts only (interface, stream, time, format)
            self.send_header("Content-Disposition", f'attachment; filename="{payload.filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        # Only failures: paths hold no secrets, but a line per page refresh is noise
        if len(args) >= 2 and str(args[1])[:1] in "45":
            sys.stderr.write(f"eaglegate-quarantine: {self.command} {self.path.split('?')[0]} -> {args[1]}\n")


def main(argv):
    port = int(argv[1]) if len(argv) > 1 else DEFAULT_PORT
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.daemon_threads = True
    server.app = ReviewApp()
    print(f"eaglegate-quarantine: serving {ROUTE_PREFIX} on port {port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main(sys.argv)
