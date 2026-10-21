"""Minimal JSON-RPC client for MCP Streamable HTTP. Stdlib only.

Speaks just enough of the protocol for the probe:
  POST <url> with a JSON-RPC message, capture the ``Mcp-Session-Id``
  response header, then ``notifications/initialized`` handshake.
  Responses may arrive inline on the POST body (plain JSON or SSE)
  or be fetched later with a GET poll carrying the session header.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from . import __version__

SESSION_HEADER = "Mcp-Session-Id"


class McpHttpError(Exception):
    """The server answered with an HTTP error or unreachable transport."""


class StreamableHttpClient:
    """One logical MCP client session over Streamable HTTP."""

    def __init__(self, url: str, timeout: float = 10.0) -> None:
        self.url = url
        self.timeout = timeout
        self.session_id: str | None = None

    # -- low-level HTTP -------------------------------------------------
    def _headers(self) -> dict:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers[SESSION_HEADER] = self.session_id
        return headers

    def _capture_session(self, resp) -> None:
        for key, value in resp.headers.items():
            if key.lower() == SESSION_HEADER.lower():
                self.session_id = value
                break

    def _post(self, payload: dict):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=data, headers=self._headers(), method="POST"
        )
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            raise McpHttpError(
                f"POST {self.url} -> HTTP {exc.code}: {body[:300]}"
            ) from exc
        body = resp.read().decode("utf-8", "replace")
        self._capture_session(resp)
        return resp.status, resp.headers.get("Content-Type", ""), body

    def _get(self):
        req = urllib.request.Request(
            self.url, headers=self._headers(), method="GET"
        )
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            raise McpHttpError(
                f"GET {self.url} -> HTTP {exc.code}: {body[:300]}"
            ) from exc
        body = resp.read().decode("utf-8", "replace")
        return resp.status, resp.headers.get("Content-Type", ""), body

    # -- response parsing ----------------------------------------------
    @staticmethod
    def _as_list(obj):
        return obj if isinstance(obj, list) else [obj]

    @classmethod
    def parse_responses(cls, body: str, content_type: str = "") -> list:
        """Extract JSON-RPC response objects from a JSON or SSE body."""
        responses: list = []
        text = (body or "").strip()
        if not text:
            return responses
        is_sse = (
            "text/event-stream" in content_type
            or text.startswith("data:")
            or text.startswith("event:")
            or "\ndata:" in text
        )
        if is_sse:
            for line in text.splitlines():
                line = line.strip()
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload in ("", "[DONE]"):
                    continue
                try:
                    obj = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                responses.extend(cls._as_list(obj))
        else:
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                return responses
            if not obj:
                return responses
            # poll envelope used by some servers: {"responses": [...]}
            if isinstance(obj, dict) and "jsonrpc" not in obj and "responses" in obj:
                for item in obj["responses"]:
                    responses.extend(cls._as_list(item))
            else:
                responses.extend(cls._as_list(obj))
        # drop empty / non-dict frames
        return [r for r in responses if isinstance(r, dict) and r]

    # -- MCP handshake ---------------------------------------------------
    def initialize(self) -> list:
        """Run initialize + notifications/initialized. Returns init responses."""
        payload = {
            "jsonrpc": "2.0",
            "id": "init",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mcp-idprobe", "version": __version__},
            },
        }
        _, content_type, body = self._post(payload)
        responses = self.parse_responses(body, content_type)
        try:
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        except McpHttpError:
            pass  # notifications are fire-and-forget; a 4xx/5xx here is non-fatal
        return responses

    def call_tool(self, name: str, arguments: dict, req_id) -> list:
        """Send tools/call. Returns any responses delivered inline."""
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        _, content_type, body = self._post(payload)
        return self.parse_responses(body, content_type)

    def poll(self) -> list:
        """Fetch responses queued for this session (GET with session header)."""
        _, content_type, body = self._get()
        return self.parse_responses(body, content_type)


def response_texts(response: dict) -> list:
    """Pull human-readable text out of a tools/call result object."""
    texts: list = []
    result = response.get("result")
    if not isinstance(result, dict):
        return texts
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                texts.append(str(item.get("text", "")))
    for key in ("output", "text"):
        value = result.get(key)
        if isinstance(value, str):
            texts.append(value)
    return texts
