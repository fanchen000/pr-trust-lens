"""Command-line interface for deterministic local scanning."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .scanner import Finding, ScanError, scan

LEVEL = {"low": 1, "medium": 2, "high": 3}
RULE_TITLES = {
    "PTL001": "Untrusted event input in privileged AI-agent job",
    "PTL002": "Event-controlled input reaches privileged AI-agent job",
    "PTL003": "Untrusted PR head checkout near privileged AI agent",
    "PTL004": "Unverified indirect input on privileged event",
    "PTL005": "Broad write permissions on AI-agent job",
    "PTL006": "Unknown effective token scope for untrusted input",
    "PTL007": "Local reusable-workflow AI-agent trust crossing",
}


def fingerprint(f: Finding) -> str:
    """Stable across output order and source line insertions (not a CVE ID)."""
    pieces = [f.rule_id, f.path.replace("\\", "/"), f.job, f.evidence]
    return hashlib.sha256("\x00".join(pieces).encode("utf-8")).hexdigest()[:24]


def _gh_escape(value: str, *, property_value: bool = False) -> str:
    """Escape user-controlled strings according to GitHub runner commands."""
    escaped = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        escaped = escaped.replace(":", "%3A").replace(",", "%2C")
    return escaped


def github_annotations(findings: list[Finding]) -> list[str]:
    """Each entry is precisely one intentionally formed workflow command."""
    output = []
    for f in findings:
        level = {"high": "error", "medium": "warning", "low": "notice"}[f.severity]
        path = _gh_escape(f.path.replace("\\", "/"), property_value=True)
        title = _gh_escape(f"PR Trust Lens {f.rule_id}", property_value=True)
        msg = _gh_escape(f"{f.message} Job: {f.job}. Evidence: {f.evidence}. Fix: {f.remediation}")
        output.append(f"::{level} file={path},line={max(1, f.line)},title={title}::{msg}")
    return output


def _plain(value: str) -> str:
    """Do not let a hostile YAML name forge runner commands via log newlines."""
    return re.sub(r"[\x00-\x1f\x7f]", lambda m: ascii(m.group(0))[1:-1], value)


def sarif(findings: list[Finding]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in findings:
        rules[f.rule_id] = {
            "id": f.rule_id,
            "shortDescription": {"text": RULE_TITLES.get(f.rule_id, f.rule_id)},
            "fullDescription": {"text": f.remediation},
            "properties": {"tags": ["security"]},
        }
        results.append({
            "ruleId": f.rule_id,
            "level": {"high": "error", "medium": "warning", "low": "note"}[f.severity],
            "message": {"text": f.message + " Fix: " + f.remediation},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.path.replace("\\", "/")},
                "region": {"startLine": f.line}}}],
            "partialFingerprints": {"pr-trust-lens/v1": fingerprint(f)},
            "properties": {"evidence": f.evidence, "job": f.job},
        })
    return {"version": "2.1.0", "$schema":
            "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "PR Trust Lens",
                                       "version": __version__,
                                       "informationUri": "https://github.com/fanchen000/pr-trust-lens",
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
    cmd.add_argument("--format", choices=["human", "json", "sarif", "github"],
                     default="human")
    cmd.add_argument("--fail-on", choices=["low", "medium", "high", "none"], default="high")
    args = parser.parse_args(argv)
    try:
        findings, scanned = scan(Path(args.path))
    except ScanError as exc:
        print(f"pr-trust-lens: input error: {_plain(str(exc))}", file=sys.stderr)
        return 2
    if args.format == "sarif":
        print(json.dumps(sarif(findings), indent=2))
    elif args.format == "json":
        print(json.dumps({"version": __version__, "workflows_scanned": scanned,
                          "findings": [f.json() for f in findings]}, indent=2))
    elif args.format == "github":
        for annotation in github_annotations(findings):
            print(annotation)
    else:
        print(f"PR Trust Lens: scanned {scanned} workflow(s), found {len(findings)} signal(s)")
        for f in findings:
            print(f"\n[{f.severity.upper()}] {f.rule_id} {_plain(f.path)}:{f.line} (job: {_plain(f.job)})")
            print(f"  {_plain(f.message)}\n  Evidence: {_plain(f.evidence)}\n  Fix: {_plain(f.remediation)}")
        if not findings:
            print("No supported risk patterns identified (not a security guarantee).")
    return int(args.fail_on != "none" and
               any(LEVEL[f.severity] >= LEVEL[args.fail_on] for f in findings))


if __name__ == "__main__":
    sys.exit(main())

