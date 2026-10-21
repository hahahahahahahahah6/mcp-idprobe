"""Localhost fixtures for testing the probe. NOT for production use.

Two fake MCP Streamable HTTP servers sharing one protocol:

* ``VulnerableMcpServer`` reproduces the CVE-2026-111770 pattern: ONE shared
  ``pending`` dict keyed by the *bare* JSON-RPC request id across all
  sessions. A small fixed worker delay guarantees both clients' colliding
  registrations land before any response is routed, so the crossing is
  deterministic: the first client's tool result is delivered to the second
  client's outbox, every run.

* ``FixedMcpServer`` namespaces in-flight requests per session
  (``(session_id, request_id)``), i.e. the 2.3.0 behavior: every response
  reaches the session that asked for it.

Protocol (fixture-local):
  POST /mcp  JSON-RPC body; ``Mcp-Session-Id`` header after initialize.
    - ``initialize`` -> 200 + JSON-RPC result + ``Mcp-Session-Id`` header.
    - ``notifications/*`` -> 202, empty.
    - ``tools/call`` -> 202, empty; result queued to a session outbox.
  GET /mcp   with ``Mcp-Session-Id`` -> 200 ``{"responses": [...]}``,
    clearing that session's outbox.
"""
from __future__ import annotations

import json
import queue
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SESSION_HEADER = "Mcp-Session-Id"
WORKER_DELAY = 0.10  # s; long enough for both colliding registrations to land


class _FixtureCore(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, vulnerable: bool):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.vulnerable = vulnerable
        self.lock = threading.Lock()
        self.sessions: set[str] = set()
        # THE bug vs the fix live in how this dict is keyed:
        #   vulnerable -> pending[raw_request_id] = session_id        (collides)
        #   fixed      -> pending[(session_id, raw_request_id)] = session_id
        self.pending: dict = {}
        self.outbox: dict[str, list] = {}
        self.jobs: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._work, daemon=True)
        self._worker.start()

    def _work(self):
        while not self._stop.is_set():
            try:
                job = self.jobs.get(timeout=0.05)
            except queue.Empty:
                continue
            time.sleep(WORKER_DELAY)
            req_id, session_id, secret = job
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": secret}]},
            }
            with self.lock:
                if self.vulnerable:
                    # BUG: bare id -- the last session to register this id wins,
                    # so an earlier session's response is routed to the wrong
                    # client. This is the CVE-2026-111770 pattern.
                    owner = self.pending.get(req_id, session_id)
                else:
                    # FIX (2.3.0 behavior): ids are namespaced per session.
                    owner = self.pending.get((session_id, req_id), session_id)
                self.outbox.setdefault(owner, []).append(response)
            self.jobs.task_done()

    def shutdown_fixture(self):
        self._stop.set()
        self.shutdown()
        self.server_close()


class _Handler(BaseHTTPRequestHandler):
    server_version = "mcp-idprobe-fixture/0.1.0"

    def log_message(self, *args):  # keep test output clean
        pass

    def _send_json(self, obj, status=200, extra_headers=None):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        return json.loads(raw.decode("utf-8")) if raw else {}

    def _session(self):
        return self.headers.get(SESSION_HEADER)

    def do_POST(self):
        core: _FixtureCore = self.server
        try:
            msg = self._read_json()
        except Exception:
            self._send_json({"error": "bad json"}, status=400)
            return
        method = msg.get("method", "")

        if method == "initialize":
            sid = uuid.uuid4().hex
            with core.lock:
                core.sessions.add(sid)
                core.outbox.setdefault(sid, [])
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mcp-idprobe-fixture", "version": "0.1.0"},
            }
            self._send_json(
                {"jsonrpc": "2.0", "id": msg.get("id"), "result": result},
                extra_headers={SESSION_HEADER: sid},
            )
            return

        session_id = self._session()
        with core.lock:
            known = session_id in core.sessions
        if not known:
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "id": msg.get("id"),
                    "error": {"code": -32000, "message": "unknown session"},
                },
                status=400,
            )
            return

        if method.startswith("notifications/"):
            self._send_json({}, status=202)
            return

        if method == "tools/call":
            req_id = msg.get("id")
            args = (msg.get("params") or {}).get("arguments") or {}
            secret = args.get("text", "")
            key = req_id if core.vulnerable else (session_id, req_id)
            with core.lock:
                core.pending[key] = session_id
                core.jobs.put((req_id, session_id, secret))
            self._send_json({}, status=202)
            return

        self._send_json(
            {
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "error": {"code": -32601, "message": "method not found"},
            },
            status=404,
        )

    def do_GET(self):
        core: _FixtureCore = self.server
        session_id = self._session()
        with core.lock:
            if session_id not in core.sessions:
                responses = None
            else:
                responses = core.outbox.get(session_id, [])
                core.outbox[session_id] = []
        if responses is None:
            self._send_json({"error": "unknown session"}, status=400)
            return
        self._send_json({"responses": responses})


class FixtureServer:
    """Context manager: ``with FixtureServer(vulnerable=True) as fx:``."""

    def __init__(self, vulnerable: bool):
        self.vulnerable = vulnerable
        self._core: _FixtureCore | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "FixtureServer":
        self._core = _FixtureCore(self.vulnerable)
        self._thread = threading.Thread(
            target=self._core.serve_forever, daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, *exc):
        if self._core is not None:
            self._core.shutdown_fixture()
        return False

    @property
    def url(self) -> str:
        port = self._core.server_address[1]
        return f"http://127.0.0.1:{port}/mcp"


def VulnerableMcpServer() -> FixtureServer:
    """Fixture reproducing the CVE-2026-111770 leak pattern."""
    return FixtureServer(vulnerable=True)


def FixedMcpServer() -> FixtureServer:
    """Fixture with per-session id namespaces (2.3.0 behavior)."""
    return FixtureServer(vulnerable=False)
