"""Command-line interface for deterministic local scanning."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .scanner import Finding, ScanError, scan

LEVEL = {"low": 1, "medium": 2, "high": 3}


def sarif(findings: list[Finding]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in findings:
        rules[f.rule_id] = {"id": f.rule_id, "shortDescription": {"text": f.message},
                            "help": {"text": f.remediation}}
        results.append({
            "ruleId": f.rule_id,
            "level": {"high": "error", "medium": "warning", "low": "note"}[f.severity],
            "message": {"text": f.message + " Fix: " + f.remediation},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.path.replace("\\", "/")},
                "region": {"startLine": f.line}}}],
            "properties": {"evidence": f.evidence, "job": f.job},
        })
    return {"version": "2.1.0", "$schema":
            "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "PR Trust Lens",
                                       "version": __version__,
                                       "rules": [rules[key] for key in sorted(rules)]}},
                      "results": results}]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pr-trust-lens",
        description="Explainable trust-boundary checks for AI coding agent CI workflows.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("scan", help="scan a repository or a workflow YAML file")
    cmd.add_argument("path", nargs="?", default=".")
    cmd.add_argument("--format", choices=["human", "json", "sarif"], default="human")
    cmd.add_argument("--fail-on", choices=["low", "medium", "high", "none"], default="high")
    args = parser.parse_args(argv)
    try:
        findings, scanned = scan(Path(args.path))
    except ScanError as exc:
        print(f"pr-trust-lens: input error: {exc}", file=sys.stderr)
        return 2
    if args.format == "sarif":
        print(json.dumps(sarif(findings), indent=2))
    elif args.format == "json":
        print(json.dumps({"version": __version__, "workflows_scanned": scanned,
                          "findings": [f.json() for f in findings]}, indent=2))
    else:
        print(f"PR Trust Lens: scanned {scanned} workflow(s), found {len(findings)} signal(s)")
        for f in findings:
            print(f"\n[{f.severity.upper()}] {f.rule_id} {f.path}:{f.line} (job: {f.job})")
            print(f"  {f.message}\n  Evidence: {f.evidence}\n  Fix: {f.remediation}")
        if not findings:
            print("No supported risk patterns identified (not a security guarantee).")
    return int(args.fail_on != "none" and
               any(LEVEL[f.severity] >= LEVEL[args.fail_on] for f in findings))


if __name__ == "__main__":
    sys.exit(main())

