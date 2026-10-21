"""Tests for the heuristic static scan."""
import json
import os
import tempfile
import unittest

from mcp_idprobe import static_scan

VULN_TS = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";

// one server for every HTTP client -- the README anti-pattern
const server = new McpServer({ name: "shared", version: "1.0.0" });

const app = express();
app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});
"""

FIXED_TS = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";
import { randomUUID } from "crypto";

const app = express();
app.post("/mcp", async (req, res) => {
  // fresh server + transport per request, ids namespaced per session
  const server = new McpServer({ name: "per-request", version: "1.0.0" });
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
  });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});
"""

VULN_PY = """\
pending = {}  # request id -> waiter; shared across sessions


def handle_request(session_id, msg):
    req_id = msg["id"]
    pending[req_id] = session_id  # bare id: collides across sessions
"""

FIXED_PY = """\
def handle_request(session_id, msg):
    req_id = msg["id"]
    pending[(session_id, req_id)] = waiter  # namespaced per session
"""


def write_tree(files):
    tmp = tempfile.mkdtemp()
    for name, content in files.items():
        path = os.path.join(tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    return tmp


class TestStaticScan(unittest.TestCase):
    def test_flags_vulnerable_typescript(self):
        root = write_tree({"server.ts": VULN_TS})
        report = static_scan.scan_path(root)
        self.assertEqual(report["verdict"], "LIKELY_VULNERABLE_PATTERN")
        rules = {f["rule"] for f in report["findings"]}
        self.assertIn("shared-server-instance", rules)

    def test_clean_on_fixed_typescript(self):
        root = write_tree({"server.ts": FIXED_TS})
        report = static_scan.scan_path(root)
        self.assertEqual(report["verdict"], "NO_PATTERN_FOUND")

    def test_flags_vulnerable_python(self):
        root = write_tree({"server.py": VULN_PY})
        report = static_scan.scan_path(root)
        self.assertEqual(report["verdict"], "LIKELY_VULNERABLE_PATTERN")
        rules = {f["rule"] for f in report["findings"]}
        self.assertIn("bare-id-pending-map", rules)

    def test_clean_on_fixed_python(self):
        root = write_tree({"server.py": FIXED_PY})
        report = static_scan.scan_path(root)
        self.assertEqual(report["verdict"], "NO_PATTERN_FOUND")

    def test_flags_vulnerable_sdk_version(self):
        pkg = {"dependencies": {"@modelcontextprotocol/server": "^2.1.0"}}
        root = write_tree({"package.json": json.dumps(pkg)})
        report = static_scan.scan_path(root)
        rules = {f["rule"] for f in report["findings"]}
        self.assertIn("sdk-version-vulnerable", rules)

    def test_fixed_sdk_version_is_info_only(self):
        pkg = {"dependencies": {"@modelcontextprotocol/server": "^2.3.0"}}
        root = write_tree({"package.json": json.dumps(pkg)})
        report = static_scan.scan_path(root)
        self.assertEqual(report["verdict"], "NO_PATTERN_FOUND")
        rules = {f["rule"] for f in report["findings"]}
        self.assertIn("sdk-version", rules)

    def test_self_scan_flags_fixture_vulnerable_branch(self):
        fixture = os.path.join(
            os.path.dirname(__file__), "..", "src", "mcp_idprobe", "fixtures.py"
        )
        report = static_scan.scan_path(os.path.abspath(fixture))
        rules = {f["rule"] for f in report["findings"]}
        # the fixture deliberately contains the CVE pattern
        self.assertIn("bare-id-pending-map", rules)

    def test_report_is_json_serializable(self):
        root = write_tree({"server.ts": VULN_TS})
        json.dumps(static_scan.scan_path(root))


if __name__ == "__main__":
    unittest.main()
