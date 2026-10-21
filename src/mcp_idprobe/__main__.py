"""CLI: python -m mcp_idprobe --url http://127.0.0.1:PORT/mcp [--scan PATH] [--out-dir DIR]

Exit codes: 0 = PASS / no pattern found, 2 = VULNERABLE pattern found,
1 = error (bad target, handshake failure, ...).
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .prober import run_probe
from .report import build_report, render_summary, write_outputs
from .static_scan import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-idprobe",
        description=(
            "Runtime probe for MCP cross-tenant response leaking via JSON-RPC "
            "id collision (CVE-2026-111770)."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--url",
        help="Live MCP Streamable HTTP endpoint to probe, e.g. http://127.0.0.1:8000/mcp",
    )
    parser.add_argument(
        "--scan",
        metavar="PATH",
        help="Also run the heuristic static scan over a source tree or file",
    )
    parser.add_argument("--rounds", type=int, default=2, help="interleaved rounds per session (default: 2)")
    parser.add_argument(
        "--settle",
        type=float,
        default=1.0,
        help="seconds to wait for in-flight responses before polling (default: 1.0)",
    )
    parser.add_argument("--tool", default="echo", help="tool name to call (default: echo)")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    parser.add_argument("--out-dir", metavar="DIR", help="write evidence.json + summary.txt here")
    parser.add_argument("--json", action="store_true", help="print the evidence JSON to stdout")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not args.url and not args.scan:
        print("nothing to do: pass --url and/or --scan", file=sys.stderr)
        return 1

    probe = None
    if args.url:
        try:
            probe = run_probe(
                args.url,
                rounds=args.rounds,
                settle_time=args.settle,
                timeout=args.timeout,
                tool_name=args.tool,
            )
        except Exception as exc:  # noqa: BLE001 - surface as CLI error
            print(f"probe failed: {exc}", file=sys.stderr)
            return 1

    scan = scan_path(args.scan) if args.scan else None

    report = build_report(probe=probe, scan=scan)
    if args.out_dir:
        paths = write_outputs(report, args.out_dir)
        print(f"wrote {paths['evidence_json']}")
        print(f"wrote {paths['summary_txt']}")
    if args.json or not args.out_dir:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    if not args.json and args.out_dir:
        print()
        print(render_summary(report))

    bad = False
    if probe and probe.get("verdict") == "VULNERABLE":
        bad = True
    if scan and scan.get("verdict") == "LIKELY_VULNERABLE_PATTERN":
        bad = True
    return 2 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
