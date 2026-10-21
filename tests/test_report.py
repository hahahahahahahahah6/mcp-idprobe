"""Tests for the evidence report builder."""
import json
import os
import tempfile
import unittest

from mcp_idprobe.report import build_report, render_summary, write_outputs


SAMPLE_PROBE = {
    "verdict": "VULNERABLE",
    "summary": "1 crossed response(s)",
    "evidence": {
        "crossed_responses": [
            {
                "received_by": "session-B",
                "belongs_to": "session-A",
                "secret": "idprobe-A-abc",
                "response_id": "0",
                "response": {"jsonrpc": "2.0", "id": "0"},
            }
        ],
        "correctly_delivered": [],
        "missing_responses": [{"session": "session-A", "secret": "idprobe-A-abc"}],
        "responses_per_session": {"A": 0, "B": 1},
    },
}


class TestReport(unittest.TestCase):
    def test_report_is_json_serializable(self):
        report = build_report(probe=SAMPLE_PROBE, scan={"verdict": "NO_PATTERN_FOUND"})
        json.dumps(report)
        self.assertEqual(report["cve"], "CVE-2026-111770")

    def test_summary_mentions_verdict_and_leak(self):
        report = build_report(probe=SAMPLE_PROBE)
        summary = render_summary(report)
        self.assertIn("VULNERABLE", summary)
        self.assertIn("session-A", summary)
        self.assertIn("session-B", summary)
        self.assertIn("2.3.0", summary)  # remediation mentions the fixed version

    def test_write_outputs(self):
        report = build_report(probe=SAMPLE_PROBE)
        out_dir = tempfile.mkdtemp()
        paths = write_outputs(report, out_dir)
        self.assertTrue(os.path.isfile(paths["evidence_json"]))
        self.assertTrue(os.path.isfile(paths["summary_txt"]))
        with open(paths["evidence_json"], encoding="utf-8") as fh:
            loaded = json.load(fh)
        self.assertEqual(loaded["probe"]["verdict"], "VULNERABLE")


if __name__ == "__main__":
    unittest.main()
