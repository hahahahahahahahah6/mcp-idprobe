"""End-to-end tests: the probe must flag the vulnerable fixture and
pass the fixed one."""
import json
import unittest

from mcp_idprobe.fixtures import FixedMcpServer, VulnerableMcpServer
from mcp_idprobe.prober import build_verdict, run_probe


class TestProbeAgainstFixtures(unittest.TestCase):
    def test_vulnerable_fixture_is_flagged(self):
        with VulnerableMcpServer() as fx:
            result = run_probe(fx.url, rounds=2, settle_time=1.0)
        self.assertEqual(result["verdict"], "VULNERABLE")
        crossed = result["evidence"]["crossed_responses"]
        self.assertGreaterEqual(len(crossed), 1)
        # the crossed response must name both sessions involved
        entry = crossed[0]
        self.assertNotEqual(entry["received_by"], entry["belongs_to"])
        # evidence must be JSON-serializable
        json.dumps(result)

    def test_fixed_fixture_passes(self):
        with FixedMcpServer() as fx:
            result = run_probe(fx.url, rounds=2, settle_time=1.0)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["evidence"]["crossed_responses"], [])
        self.assertEqual(result["evidence"]["missing_responses"], [])
        json.dumps(result)

    def test_vulnerable_fixture_reports_missing_for_victim(self):
        with VulnerableMcpServer() as fx:
            result = run_probe(fx.url, rounds=1, settle_time=1.0)
        missing = result["evidence"]["missing_responses"]
        # session A's response was routed away, so A is missing its own
        self.assertTrue(any(m["session"] == "session-A" for m in missing))


class TestBuildVerdict(unittest.TestCase):
    def test_crossing_detected(self):
        secrets = {"A": ["sA"], "B": ["sB"]}
        responses = {
            "A": [],
            "B": [
                {"jsonrpc": "2.0", "id": "0",
                 "result": {"content": [{"type": "text", "text": "sA"}]}}
            ],
        }
        verdict = build_verdict(secrets, responses)
        self.assertEqual(verdict["verdict"], "VULNERABLE")
        self.assertEqual(len(verdict["evidence"]["crossed_responses"]), 1)

    def test_clean_run_passes(self):
        secrets = {"A": ["sA"], "B": ["sB"]}
        responses = {
            "A": [{"jsonrpc": "2.0", "id": "0",
                   "result": {"content": [{"type": "text", "text": "sA"}]}}],
            "B": [{"jsonrpc": "2.0", "id": "0",
                   "result": {"content": [{"type": "text", "text": "sB"}]}}],
        }
        verdict = build_verdict(secrets, responses)
        self.assertEqual(verdict["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
