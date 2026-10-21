"""Evidence report: machine-readable JSON + human-readable summary."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from . import __version__
from .prober import CVE_ID


REMEDIATION = (
    "Remediation: upgrade @modelcontextprotocol/server to >= 2.3.0; never "
    "share one McpServer/transport instance across HTTP clients -- create a "
    "fresh server + transport per request/session, and namespace in-flight "
    "request ids per session."
)


def build_report(probe: dict | None = None, scan: dict | None = None) -> dict:
    """Assemble the full evidence dict (JSON-serializable)."""
    return {
        "tool": "mcp-idprobe",
        "version": __version__,
        "cve": CVE_ID,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "probe": probe,
        "static_scan": scan,
    }


def render_summary(report: dict) -> str:
    """One-page human summary of the evidence."""
    lines = [
        f"mcp-idprobe {report['version']} -- {report['cve']} evidence report",
        f"generated: {report['generated_at']}",
        "",
    ]
    probe = report.get("probe")
    if probe:
        lines += [
            "[runtime probe]",
            f"target:  {probe.get('target')}",
            f"verdict: {probe.get('verdict')}",
            f"detail:  {probe.get('summary')}",
        ]
        ev = (probe.get("evidence") or {})
        for crossed in ev.get("crossed_responses", []):
            lines.append(
                f"  LEAK: {crossed['belongs_to']} -> {crossed['received_by']} "
                f"(response id {crossed['response_id']!r}, "
                f"secret {crossed['secret']!r})"
            )
        missing = ev.get("missing_responses", [])
        if missing:
            lines.append(
                f"  note: {len(missing)} request(s) never reached their owner "
                "(consistent with misrouting)."
            )
        lines.append("")
    scan = report.get("static_scan")
    if scan:
        lines += [
            "[static scan]",
            f"target:  {scan.get('target')} ({scan.get('files_scanned')} files)",
            f"verdict: {scan.get('verdict')}",
            f"detail:  {scan.get('summary')}",
        ]
        for finding in scan.get("findings", [])[:10]:
            loc = finding["file"]
            if finding["line"]:
                loc += f":{finding['line']}"
            lines.append(f"  [{finding['severity']}] {finding['rule']} -- {loc}")
        if len(scan.get("findings", [])) > 10:
            lines.append(
                f"  ... and {len(scan['findings']) - 10} more (see evidence.json)"
            )
        lines.append("")
    lines.append(REMEDIATION)
    return "\n".join(lines)


def write_outputs(report: dict, out_dir: str) -> dict:
    """Write evidence.json + summary.txt into out_dir. Returns paths."""
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "evidence.json")
    summary_path = os.path.join(out_dir, "summary.txt")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    with open(summary_path, "w", encoding="utf-8") as fh:
        fh.write(render_summary(report) + "\n")
    return {"evidence_json": json_path, "summary_txt": summary_path}
