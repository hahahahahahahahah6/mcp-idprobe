"""Two-session interleaving prober for CVE-2026-111770.

The CVE: in @modelcontextprotocol/server 2.0.0-2.2.0, when several clients
share one transport/McpServer instance over HTTP, the server tracks in-flight
requests by the *bare* JSON-RPC ``id``. Every client numbers its own requests
from 0, so ids collide across sessions and a response can be delivered to the
wrong client -- ordinary overlapping traffic leaks across tenants.

The probe mirrors that: two independent sessions, each numbering its probe
requests from "0", interleaved back-to-back, every request carrying a
per-client secret. If any client receives the other client's secret, the
server routes responses by bare id and the leak pattern is confirmed.
"""
from __future__ import annotations

import json
import time
import uuid

from .client import StreamableHttpClient, response_texts

CVE_ID = "CVE-2026-111770"


def _dedupe(responses: list) -> list:
    seen = set()
    unique = []
    for resp in responses:
        key = json.dumps(resp, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            unique.append(resp)
    return unique


def run_probe(
    url: str,
    rounds: int = 2,
    settle_time: float = 1.0,
    timeout: float = 10.0,
    tool_name: str = "echo",
) -> dict:
    """Run the interleaving probe against a live Streamable HTTP endpoint.

    Returns a JSON-serializable dict with ``verdict`` ("VULNERABLE" or "PASS")
    and ``evidence``.
    """
    clients = {
        "A": StreamableHttpClient(url, timeout=timeout),
        "B": StreamableHttpClient(url, timeout=timeout),
    }
    started_at = time.time()

    # 1. handshake: two independent sessions
    handshake_ok = {}
    for tag, client in clients.items():
        try:
            client.initialize()
            handshake_ok[tag] = bool(client.session_id)
        except Exception as exc:  # noqa: BLE001 - reported, not fatal
            handshake_ok[tag] = False
            handshake_ok[f"{tag}_error"] = str(exc)

    # 2. interleave: each client numbers its own requests from "0",
    #    exactly like the per-client counters in the CVE write-up.
    secrets: dict[str, list[str]] = {"A": [], "B": []}
    inline: dict[str, list] = {"A": [], "B": []}
    send_errors: list = []
    for i in range(rounds):
        for tag in ("A", "B"):
            secret = f"idprobe-{tag}-{uuid.uuid4().hex[:8]}-r{i}"
            secrets[tag].append(secret)
            try:
                inline[tag].extend(
                    clients[tag].call_tool(tool_name, {"text": secret}, req_id=str(i))
                )
            except Exception as exc:  # noqa: BLE001
                send_errors.append({"session": tag, "round": i, "error": str(exc)})

    # 3. let in-flight work settle, then poll each session's queue
    time.sleep(settle_time)
    polled: dict[str, list] = {"A": [], "B": []}
    for tag, client in clients.items():
        try:
            polled[tag] = client.poll()
        except Exception:  # noqa: BLE001 - server may not support polling
            polled[tag] = []

    all_responses = {
        tag: _dedupe(inline[tag] + polled[tag]) for tag in ("A", "B")
    }

    verdict = build_verdict(secrets, all_responses)
    verdict["target"] = url
    verdict["cve"] = CVE_ID
    verdict["rounds"] = rounds
    verdict["tool"] = tool_name
    verdict["duration_s"] = round(time.time() - started_at, 2)
    verdict["handshake"] = handshake_ok
    verdict["send_errors"] = send_errors
    return verdict


def build_verdict(secrets: dict[str, list[str]], all_responses: dict) -> dict:
    """Attribute every response to its secret's owner; detect crossings."""
    secret_owner = {}
    for tag, own_secrets in secrets.items():
        for secret in own_secrets:
            secret_owner[secret] = tag

    crossed: list = []
    correct: list = []
    seen_own: dict[str, set] = {"A": set(), "B": set()}

    for tag, responses in all_responses.items():
        for resp in responses:
            blob = "\n".join(response_texts(resp))
            if not blob:
                continue
            for secret, owner in secret_owner.items():
                if secret not in blob:
                    continue
                entry = {
                    "received_by": f"session-{tag}",
                    "belongs_to": f"session-{owner}",
                    "secret": secret,
                    "response_id": resp.get("id"),
                    "response": resp,
                }
                if owner != tag:
                    crossed.append(entry)
                else:
                    seen_own[tag].add(secret)
                    correct.append(entry)

    missing = []
    for tag, own_secrets in secrets.items():
        for secret in own_secrets:
            if secret not in seen_own[tag]:
                missing.append({"session": f"session-{tag}", "secret": secret})

    vulnerable = len(crossed) > 0
    return {
        "verdict": "VULNERABLE" if vulnerable else "PASS",
        "summary": (
            f"{len(crossed)} crossed response(s): a client received another "
            f"client's tool result -- {CVE_ID} leak pattern confirmed."
            if vulnerable
            else "All responses were delivered to the session that requested "
            "them; no cross-tenant leaking observed."
        ),
        "evidence": {
            "crossed_responses": crossed,
            "correctly_delivered": correct,
            "missing_responses": missing,
            "responses_per_session": {
                tag: len(all_responses[tag]) for tag in all_responses
            },
        },
    }
