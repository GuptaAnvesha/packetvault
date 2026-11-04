"""PacketVault web dashboard: stdlib HTTP server + JSON API (``packetvault ui``)."""

from __future__ import annotations

import json
import mimetypes
import os
import re
import threading
import traceback
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .. import nmac, search, vault_crypto
from .api import Workspace
from .tools import ToolError, interfaces, open_in_wireshark

STATIC = Path(__file__).resolve().parent / "static"
MAX_JSON = 256 * 1024
MAX_UPLOAD = 512 * 1024 * 1024
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")

_CASE_ROUTE = re.compile(r"^/api/cases/([^/]+)(?:/([a-z\-]+))?$")


def route_get(ws: Workspace, path: str, q: dict) -> dict | list:
    if path == "/api/overview":
        return ws.overview()
    if path == "/api/captures":
        return {"files": ws.list_captures(), "live": ws.live.status()}
    if path == "/api/interfaces":
        return {"interfaces": interfaces()}
    if path == "/api/cases":
        return {"cases": ws.list_cases()}
    if path == "/api/security":
        return ws.security()
    if path == "/api/nmac":
        return ws.nmac_trace(q.get("msg", ["record #1500: 192.168.56.101 -> 192.168.56.10:4444 SYN"])[0])
    if path == "/api/nmac/length-extension":
        return nmac.length_extension_demo(os.urandom(32))
    if path == "/api/nmac/bench":
        return {"rows": nmac.benchmark()}
    m = _CASE_ROUTE.match(path)
    if m and m.group(2) is None:
        return ws.case_detail(unquote(m.group(1)))
    raise LookupError(path)


def route_post(ws: Workspace, path: str, body: dict) -> dict:
    simple = {
        "/api/keys": lambda: ws.generate_keys(bool(body.get("custodian", True)), bool(body.get("overwrite"))),
        "/api/keys/custodian": ws.ensure_custodian,
        "/api/captures/sample": lambda: ws.sample(int(body.get("seed", 7))),
        "/api/captures/preview": lambda: ws.preview(str(body.get("file", "")), str(body.get("backend", "builtin")),
                                                    int(body.get("limit", 200)), int(body.get("threshold", 15)),
                                                    float(body.get("window", 10.0))),
        "/api/captures/crosscheck": lambda: ws.crosscheck(str(body.get("file", ""))),
        "/api/captures/labels": lambda: ws.set_labels(str(body.get("file", "")),
                                                      [str(s) for s in body.get("scanners", [])][:50]),
        "/api/captures/delete": lambda: ws.delete_capture(str(body.get("file", ""))),
        "/api/captures/open": lambda: {"command": open_in_wireshark(ws.capture_path(str(body.get("file", ""))))},
        "/api/live/start": lambda: ws.live.start(str(body.get("interface", "")), str(body.get("filter", "")),
                                                 int(body.get("seconds", 60))),
        "/api/live/stop": lambda: ws.live.stop() or {},
        "/api/nmap": lambda: ws.nmap(body),
        "/api/cases/seal": lambda: ws.seal(body),
        "/api/bench": lambda: ws.run_bench(body),
    }
    if path in simple:
        return simple[path]()
    m = _CASE_ROUTE.match(path)
    if m and m.group(2):
        case_id, action = unquote(m.group(1)), m.group(2)
        actions = {
            "verify": lambda: ws.verify(case_id, body),
            "tamper": lambda: ws.tamper(case_id, body),
            "query": lambda: ws.query(case_id, body),
            "delete": lambda: ws.delete_case(case_id),
            "matrix": lambda: ws.tamper_matrix(case_id, body),
            "nmac-chain": lambda: ws.nmac_chain_example(case_id, body),
        }
        if action in actions:
            return actions[action]()
    raise LookupError(path)


class Handler(BaseHTTPRequestHandler):
    server_version = "PacketVault"
    sys_version = ""
    ws: Workspace
    allowed_hosts: set[str]

    def log_message(self, fmt, *args):
        pass

    # ------------------------------------------------------------------ responses

    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj) -> None:
        self._send(status, json.dumps(obj, default=str).encode(), "application/json")

    def _host_ok(self) -> bool:
        if (self.headers.get("Host") or "").lower() in self.allowed_hosts:
            return True
        self._json(HTTPStatus.FORBIDDEN, {"error": "host not allowed"})
        return False

    # ------------------------------------------------------------------ GET

    def do_GET(self):
        if not self._host_ok():
            return
        url = urlparse(self.path)
        path = url.path
        if path == "/" or path.startswith("/static/"):
            return self._static("index.html" if path == "/" else path[len("/static/"):])
        if path.startswith("/files/captures/"):
            return self._download(lambda: self.ws.capture_path(unquote(path[len("/files/captures/"):])),
                                  "application/vnd.tcpdump.pcap")
        m = re.match(r"^/files/cases/([^/]+)/([A-Za-z0-9_.\-]+)$", path)
        if m:
            return self._download(lambda: _case_file(self.ws, unquote(m.group(1)), m.group(2)), None)
        m = re.match(r"^/files/bench/([A-Za-z0-9_.\-]+\.png)$", path)
        if m:
            return self._download(lambda: _bench_file(self.ws, m.group(1)), "image/png", inline=True)
        self._dispatch(lambda: route_get(self.ws, path, parse_qs(url.query)))

    def _static(self, name: str) -> None:
        file = (STATIC / name).resolve()
        if STATIC.resolve() not in file.parents or not file.is_file():
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        ctype = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or "javascript" in ctype:
            ctype += "; charset=utf-8"
        self._send(HTTPStatus.OK, file.read_bytes(), ctype)

    def _download(self, resolve, ctype: str | None, inline: bool = False) -> None:
        try:
            file = resolve()
        except (ValueError, FileNotFoundError):
            return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        ctype = ctype or mimetypes.guess_type(file.name)[0] or "application/octet-stream"
        disp = "inline" if inline else f'attachment; filename="{file.name}"'
        self._send(HTTPStatus.OK, file.read_bytes(), ctype, {"Content-Disposition": disp})

    # ------------------------------------------------------------------ POST

    def do_POST(self):
        if not self._host_ok():
            return
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).netloc.lower() != (self.headers.get("Host") or "").lower():
            return self._json(HTTPStatus.FORBIDDEN, {"error": "cross-origin request blocked"})
        url = urlparse(self.path)
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        length = int(self.headers.get("Content-Length") or 0)

        if url.path == "/api/captures/upload":
            if ctype != "application/octet-stream":
                return self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "octet-stream body required"})
            if length > MAX_UPLOAD:
                return self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "capture too large (512 MiB max)"})
            data = self.rfile.read(length)
            name = parse_qs(url.query).get("name", ["upload.pcap"])[0]
            return self._dispatch(lambda: self.ws.upload(name, data))

        if ctype != "application/json":
            return self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "JSON body required"})
        if length > MAX_JSON:
            return self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body too large"})
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON"})
        self._dispatch(lambda: route_post(self.ws, url.path, body))

    def _dispatch(self, fn) -> None:
        try:
            self._json(HTTPStatus.OK, fn())
        except LookupError:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except FileNotFoundError as exc:
            self._json(HTTPStatus.NOT_FOUND, {"error": f"not found: {exc}"})
        except search.IndexIntegrityError as exc:
            self._json(HTTPStatus.CONFLICT, {"error": f"search index rejected: {exc}"})
        except vault_crypto.DecryptionError:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "wrong passphrase, or the container was modified (GCM tag check failed)"})
        except (ValueError, ToolError, RuntimeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - show unexpected errors in the dashboard
            traceback.print_exc()
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})


def _case_file(ws: Workspace, case_id: str, name: str) -> Path:
    if name not in ("report.json", "report.sig", "report.txt", "report.pdf", "evidence.db.enc", "search.idx"):
        raise ValueError(name)
    p = ws.case_path(case_id) / name
    if not p.is_file():
        raise FileNotFoundError(name)
    return p


def _bench_file(ws: Workspace, name: str) -> Path:
    for d in (ws.bench_dir, Path(__file__).resolve().parents[2] / "docs" / "benchmarks"):
        if (d / name).is_file():
            return d / name
    raise FileNotFoundError(name)


def make_server(host: str, port: int, workspace: Path) -> tuple[ThreadingHTTPServer, Workspace]:
    ws = Workspace(workspace, bind_host=host)
    handler = type("PVHandler", (Handler,), {"ws": ws, "allowed_hosts": set()})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    real_port = server.server_address[1]
    handler.allowed_hosts = {f"{h}:{real_port}" for h in ("127.0.0.1", "localhost", host)}
    return server, ws


def run(host: str, port: int, workspace: Path, open_browser: bool = True) -> int:
    server, ws = make_server(host, port, workspace)
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '') else host}:{server.server_address[1]}/"
    print(f"PacketVault dashboard: {url}")
    print(f"workspace            : {ws.root.resolve()}")
    if host not in ("127.0.0.1", "localhost"):
        print("WARNING: listening on a non-loopback address; anyone on the network can reach the dashboard")
    print("Ctrl+C to stop")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        ws.live.stop()
        server.server_close()
    return 0
