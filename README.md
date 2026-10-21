# mcp-idprobe

A runtime probe for **MCP cross-tenant response leaking via JSON-RPC id collision** — [CVE-2026-111770](https://dev.to) (`@modelcontextprotocol/server` 2.0.0–2.2.0, fixed in 2.3.0). Stdlib-only Python, no dependencies.

## The bug, in one paragraph

The MCP TypeScript SDK numbers each client's JSON-RPC requests from 0. In the affected versions, when several clients share one transport / `McpServer` instance over HTTP (exactly what the official README's hono/express/fastify/node adapter examples did), the server tracks in-flight requests by the **bare request id**. Two clients both have a request `"0"` in flight; when results complete, the lookup by bare id hands one client's tool result to the other client. No attacker is needed — ordinary overlapping traffic leaks across tenants.

## What this tool does

Against a **running** MCP server over Streamable HTTP, `mcp-idprobe`:

1. Opens **two independent client sessions** (`initialize` → `notifications/initialized`).
2. **Interleaves** `tools/call` requests from both clients, each client numbering its own requests from `"0"` — mirroring the per-client counters from the CVE.
3. Every request carries a **per-client secret token** in its arguments.
4. Collects each session's responses and attributes them by secret. If any client receives the other client's secret → **`VULNERABLE`**, with the crossed response saved as evidence. Otherwise → **`PASS`**.

It also ships a **heuristic static scan** of server source (`.ts`/`.js`/`.py`, plus `package.json` SDK version) for the anti-pattern behind the CVE: a module-scope `new McpServer(...)` / `StreamableHTTPServerTransport` reused across HTTP handlers, and pending-request tables keyed by bare id with no session scoping.

Output is a machine-readable `evidence.json` plus a human `summary.txt`.

## Differentiation: mcp-idprobe vs mcp-audit

My [`mcp-audit`](https://github.com/hahahahahahahahah6/mcp-audit) repo is a **local static attack-surface scanner**: it reads code and configuration on disk and lists where an MCP deployment *could* be attacked. `mcp-idprobe` is the opposite side of the same coin: a **runtime probe for one specific, real CVE pattern**. It talks to a live server, creates real cross-tenant traffic, and gives a deterministic pass/fail with captured evidence of responses actually crossing sessions. The two are complementary — run `mcp-audit` to find where to look, run `mcp-idprobe` to prove whether the leak is really there.

## Install

```bash
pip install mcp-idprobe
```

Or from source (no dependencies, Python ≥ 3.9):

```bash
git clone https://github.com/hahahahahahahahah6/mcp-idprobe
cd mcp-idprobe
python -m mcp_idprobe --help
```

## Usage

```bash
# Probe a live Streamable HTTP endpoint (two sessions, interleaved)
mcp-idprobe --url http://127.0.0.1:8000/mcp --out-dir ./evidence

# ...and also statically scan the server's source tree
mcp-idprobe --url http://127.0.0.1:8000/mcp --scan ./my-mcp-server/src --out-dir ./evidence

# Static scan only
mcp-idprobe --scan ./my-mcp-server/src --out-dir ./evidence

# JSON evidence to stdout (for CI)
mcp-idprobe --url http://127.0.0.1:8000/mcp --json
```

Exit codes: `0` = PASS / no pattern found, `2` = VULNERABLE pattern found, `1` = error.

Options: `--rounds N` (interleaved rounds per session, default 2), `--settle SECONDS` (wait before polling, default 1.0), `--tool NAME` (tool to call, default `echo`), `--timeout SECONDS`.

Example output (vulnerable server):

```
mcp-idprobe 0.1.0 -- CVE-2026-111770 evidence report

[runtime probe]
target:  http://127.0.0.1:8000/mcp
verdict: VULNERABLE
detail:  2 crossed response(s): a client received another client's tool result
         -- CVE-2026-111770 leak pattern confirmed.
  LEAK: session-A -> session-B (response id '0', secret 'idprobe-A-38fb4c28-r0')
  LEAK: session-A -> session-B (response id '1', secret 'idprobe-A-21572f4e-r1')
  note: 2 request(s) never reached their owner (consistent with misrouting).

Remediation: upgrade @modelcontextprotocol/server to >= 2.3.0; never share one
McpServer/transport instance across HTTP clients -- create a fresh server +
transport per request/session, and namespace in-flight request ids per session.
```

## Honest scope

- This **proves the leak pattern exists**; it is not an exploit. It only reads responses addressed to its own two sessions.
- It targets Streamable HTTP servers. Responses delivered inline on the POST body (plain JSON or SSE) are parsed; servers that queue responses expose them via a GET poll with the `Mcp-Session-Id` header — if your server delivers results some other way, point the probe at it and check whether attribution holds.
- The static scan is **heuristic**: it flags code shapes (shared instance, bare-id maps), not runtime behavior. A flagged file deserves a look, not a verdict — confirm with the live probe.
- Test against servers you own or are authorized to test. Localhost is the intended target.

## How the probe stays deterministic

The bundled test fixtures (`mcp_idprobe.fixtures`) include a fake **vulnerable** server — one shared `pending` dict keyed by bare id, like the CVE — and a **fixed** server with per-session id namespaces (the 2.3.0 behavior). The vulnerable fixture's worker completes jobs after a fixed delay so both clients' colliding registrations land before routing; the probe must flag it every run, and must pass the fixed one. The test suite asserts exactly that.

## Development

```bash
python -m unittest discover -s tests -t .   # 30 tests, stdlib only
```

## License

MIT — see [LICENSE](LICENSE).
