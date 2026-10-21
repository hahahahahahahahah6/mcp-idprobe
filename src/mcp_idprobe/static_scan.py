"""Heuristic static scan for the CVE-2026-111770 shared-transport anti-pattern.

Looks for the code shapes behind the advisory:

* one ``McpServer`` instance created at module scope and reused across HTTP
  request handlers (the pattern the official README's hono/express/fastify/
  node examples used);
* a ``StreamableHTTPServerTransport`` shared the same way;
* an in-flight/pending request table keyed by the *bare* JSON-RPC id with no
  session scoping;
* ``@modelcontextprotocol/server`` pinned to the vulnerable range 2.0.0-2.2.0.

This is a heuristic triage aid, NOT a proof of vulnerability: it flags code
shapes, it cannot see runtime wiring. Findings carry severity + line numbers
so a human can confirm.
"""
from __future__ import annotations

import json
import os
import re

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# -- TypeScript / JavaScript ---------------------------------------------
_TS_MODULE_SCOPE_SERVER = re.compile(
    r"^(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*new\s+McpServer\s*\("
)
_TS_MODULE_SCOPE_TRANSPORT = re.compile(
    r"^(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*new\s+StreamableHTTPServerTransport\s*\("
)
_TS_HTTP_HANDLER = re.compile(
    r"app\.(post|all|use|get)\s*\(|createServer\s*\(|Bun\.serve|Deno\.serve|"
    r"addEventListener\s*\(\s*['\"]fetch['\"]|export\s+default\s*\{[^}]*fetch"
)
_TS_BARE_ID_MAP = re.compile(
    r"(pending\w*|inflight\w*|in_flight\w*|outstanding\w*|requests\w*)"
    r"\s*(\[\s*(?:request\.id|req\.id|msg\.id|id)\s*\]|\.get\s*\(\s*(?:request\.id|req\.id|msg\.id|id)\s*\)"
    r"|\.set\s*\(\s*(?:request\.id|req\.id|msg\.id|id)\s*,)"
)
_TS_SESSION_MENTION = re.compile(r"sessionId|session_id|mcp-session-id", re.IGNORECASE)

# -- Python ---------------------------------------------------------------
_PY_MODULE_SCOPE_PENDING = re.compile(
    r"^(pending\w*|in_flight\w*|outstanding\w*)\s*=\s*(\{\}|dict\s*\(\s*\))"
)
_PY_BARE_ID_KEY = re.compile(
    r"(?:self\.)?(pending\w*|in_flight\w*|outstanding\w*)"
    r"\s*(?:\[\s*"
    r"(?:msg\s*\[\s*['\"]id['\"]\s*\]|request_id|req_id|request\.id|\bid\b)\s*\]"
    r"|\.get\s*\(\s*(?:req_id|request_id|request\.id|\bid\b)\s*[,)])"
)
_PY_SESSION_KEY = re.compile(r"\(\s*session", re.IGNORECASE)

_SCAN_EXTENSIONS = (".ts", ".js", ".mjs", ".cjs", ".py")


def _finding(rule, severity, path, line, detail):
    return {
        "rule": rule,
        "severity": severity,
        "file": path,
        "line": line,
        "detail": detail,
    }


def _scan_typescript(path: str, lines: list[str]) -> list:
    findings = []
    has_handler = any(_TS_HTTP_HANDLER.search(l) for l in lines)
    has_session_mention = any(_TS_SESSION_MENTION.search(l) for l in lines)
    for i, line in enumerate(lines, 1):
        if _TS_MODULE_SCOPE_SERVER.match(line):
            detail = (
                "McpServer instantiated at module scope; if this instance is "
                "reused across HTTP request handlers, all clients share one "
                "id namespace (CVE-2026-111770 pattern)."
            )
            if has_handler:
                detail += " File also defines HTTP route handlers."
            findings.append(
                _finding("shared-server-instance", "high", path, i, detail)
            )
        if _TS_MODULE_SCOPE_TRANSPORT.match(line):
            findings.append(
                _finding(
                    "shared-transport",
                    "high",
                    path,
                    i,
                    "StreamableHTTPServerTransport instantiated at module "
                    "scope; transports must be per-request/per-session.",
                )
            )
        m = _TS_BARE_ID_MAP.search(line)
        if m:
            snippet = line.strip()[:120]
            if not _TS_SESSION_MENTION.search(line):
                findings.append(
                    _finding(
                        "bare-id-pending-map",
                        "high",
                        path,
                        i,
                        "In-flight request table keyed by bare request id with "
                        f"no session scoping visible: `{snippet}`. Colliding "
                        "ids across clients misroute responses.",
                    )
                )
    if has_handler and not has_session_mention and any(
        f["rule"] in ("shared-server-instance", "shared-transport")
        for f in findings
    ):
        findings.append(
            _finding(
                "sessionless-routing",
                "medium",
                path,
                0,
                "HTTP handlers present but no session-id handling found in "
                "this file; responses may not be attributed per session.",
            )
        )
    return findings


def _scan_python(path: str, lines: list[str]) -> list:
    findings = []
    for i, line in enumerate(lines, 1):
        if _PY_MODULE_SCOPE_PENDING.match(line):
            findings.append(
                _finding(
                    "shared-pending-dict",
                    "high",
                    path,
                    i,
                    "Pending-request dict at module scope: shared across all "
                    "sessions/threads unless keyed per session.",
                )
            )
        m = _PY_BARE_ID_KEY.search(line)
        if m and not _PY_SESSION_KEY.search(line):
            snippet = line.strip()[:120]
            findings.append(
                _finding(
                    "bare-id-pending-map",
                    "high",
                    path,
                    i,
                    "Pending table keyed by bare request id with no session "
                    f"in the key: `{snippet}`. Colliding ids across clients "
                    "misroute responses (CVE-2026-111770 pattern).",
                )
            )
    return findings


def _vuln_range(version: str) -> bool:
    """True if a @modelcontextprotocol/server spec is inside 2.0.0-2.2.0."""
    v = version.strip().lstrip("^~>=< ")
    parts = re.split(r"[.\-+]", v)
    try:
        nums = [int(p) for p in parts[:3]]
    except ValueError:
        return False
    while len(nums) < 3:
        nums.append(0)
    return (2, 0, 0) <= tuple(nums) <= (2, 2, 999)


def _scan_package_json(path: str) -> list:
    findings = []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return findings
    deps = {}
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        deps.update(data.get(section) or {})
    spec = deps.get("@modelcontextprotocol/server")
    if spec and _vuln_range(spec):
        findings.append(
            _finding(
                "sdk-version-vulnerable",
                "high",
                path,
                0,
                f"@modelcontextprotocol/server {spec} is in the vulnerable "
                "range 2.0.0-2.2.0 for CVE-2026-111770; upgrade to >= 2.3.0.",
            )
        )
    elif spec:
        findings.append(
            _finding(
                "sdk-version",
                "info",
                path,
                0,
                f"@modelcontextprotocol/server {spec} is outside the "
                "2.0.0-2.2.0 vulnerable range.",
            )
        )
    return findings


def scan_file(path: str) -> list:
    """Scan one file; returns a list of finding dicts."""
    findings = []
    name = os.path.basename(path)
    if name == "package.json":
        return _scan_package_json(path)
    if not path.endswith(_SCAN_EXTENSIONS):
        return findings
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return findings
    if path.endswith(".py"):
        findings.extend(_scan_python(path, lines))
    else:
        findings.extend(_scan_typescript(path, lines))
    return findings


def scan_path(root: str) -> dict:
    """Recursively scan a directory (or single file). Returns a report dict."""
    findings = []
    files_scanned = 0
    if os.path.isfile(root):
        targets = [root]
    else:
        targets = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d
                for d in dirnames
                if d not in ("node_modules", ".git", "__pycache__", "dist", "build")
            ]
            for fn in filenames:
                targets.append(os.path.join(dirpath, fn))
    for target in targets:
        file_findings = scan_file(target)
        if target.endswith(_SCAN_EXTENSIONS) or os.path.basename(target) == "package.json":
            files_scanned += 1
        findings.extend(file_findings)

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["file"], f["line"]))
    high = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    if high:
        verdict = "LIKELY_VULNERABLE_PATTERN"
        summary = (
            f"{high} high-severity finding(s): code matches the CVE-2026-111770 "
            "shared-transport / bare-id anti-pattern. Confirm at runtime with "
            "the live probe."
        )
    elif medium:
        verdict = "SUSPICIOUS"
        summary = "No high-severity pattern, but suspicious routing shapes found."
    else:
        verdict = "NO_PATTERN_FOUND"
        summary = "No shared-transport / bare-id anti-pattern detected (heuristic)."
    return {
        "target": root,
        "files_scanned": files_scanned,
        "verdict": verdict,
        "summary": summary,
        "findings": findings,
        "note": "Heuristic static scan: flags code shapes, not proof of runtime behavior.",
    }
