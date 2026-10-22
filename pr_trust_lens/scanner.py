"""Safe, deterministic and deliberately conservative GitHub Actions analysis."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

MAX_WORKFLOW_BYTES = 2_000_000
MAX_WORKFLOWS = 1_000

AGENT_MARKERS = (
    "anthropics/claude-code-action",
    "openai/codex",
    "google-github-actions/run-gemini-cli",
    "github/gh-aw",
    "gh-aw/",
    "codex exec",
    "claude -p",
    "claude --print",
    "gemini -p",
    "gemini --prompt",
    "opencode run",
)
UNTRUSTED_INPUTS = (
    "github.event.issue.body",
    "github.event.issue.title",
    "github.event.comment.body",
    "github.event.pull_request.body",
    "github.event.pull_request.title",
    "github.event.review.body",
    "github.event.pull_request.head.ref",
)
HIGH_TRUST_EVENTS = {"pull_request_target", "issue_comment", "workflow_run", "issues",
                     "pull_request_review", "pull_request_review_comment"}
PR_HEAD_MARKERS = ("github.event.pull_request.head.sha",
                   "github.event.pull_request.head.ref",
                   "github.head_ref", "github.event.pull_request.head.repo")
WRITE_PERMISSIONS = {"write", "write-all"}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    path: str
    line: int
    job: str
    message: str
    evidence: str
    remediation: str

    def json(self) -> dict[str, Any]:
        return asdict(self)


class ScanError(Exception):
    """An unreadable or malformed input is not treated as clean."""


def _events(doc: dict[str, Any]) -> set[str]:
    # PyYAML interprets YAML 1.1 'on' as True. GitHub Actions uses it as a key.
    event_map = doc.get("on", doc.get(True, {}))
    if isinstance(event_map, str):
        return {event_map}
    if isinstance(event_map, list):
        return {str(x) for x in event_map}
    if isinstance(event_map, dict):
        return {str(k) for k in event_map}
    return set()


def _flat(value: Any, seen: set[int] | None = None, depth: int = 0) -> str:
    if depth > 50:
        return ""
    if isinstance(value, str):
        return value
    if not isinstance(value, (dict, list, tuple)):
        return ""
    if seen is None:
        seen = set()
    if id(value) in seen:
        return ""
    seen.add(id(value))
    try:
        values = value.values() if isinstance(value, dict) else value
        return "\n".join(_flat(v, seen, depth + 1) for v in values)
    finally:
        seen.remove(id(value))


def _expression_contains(value: str, needle: str) -> bool:
    """Treat a source as an input only when it is inside an Actions expression."""
    expression_start = "$" + "{{"
    return any(needle in section.lower().split("}}", 1)[0]
               for section in value.split(expression_start)[1:]
               if "}}" in section)


def _has_agent(step: dict[str, Any]) -> bool:
    text = _flat({"uses": step.get("uses", ""), "run": step.get("run", "")}).lower()
    return any(marker in text for marker in AGENT_MARKERS)


def _permission_is_write(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in WRITE_PERMISSIONS
    if isinstance(value, dict):
        return any(_permission_is_write(v) for v in value.values())
    return False


def _job_privilege(doc: dict[str, Any], job: dict[str, Any]) -> tuple[bool, str]:
    perms = job.get("permissions", doc.get("permissions"))
    if _permission_is_write(perms):
        return True, "write-capable GITHUB_TOKEN"
    combined = _flat({"env": doc.get("env", {}), "job": job}).lower()
    if "secrets." in combined or "github.token" in combined:
        # github.token by itself is not necessarily write-capable.
        if "secrets." in combined:
            return True, "secret reference in the job or workflow"
    return False, "no explicit write token or secret detected"


def _line(text: str, evidence: str) -> int:
    # Best-effort line mapping: make no promise that an expression occurs once.
    needle = evidence.strip()
    for idx, line in enumerate(text.splitlines(), 1):
        if needle and needle in line:
            return idx
    return 1


def _finding(rule: str, severity: str, filename: str, text: str, job_id: str,
             message: str, evidence: str, remedy: str) -> Finding:
    return Finding(rule, severity, filename, _line(text, evidence), job_id,
                   message, evidence[:250], remedy)


def analyze_workflow(path: Path, display_path: str | None = None) -> list[Finding]:
    """Analyze a YAML file without evaluating scripts, expressions or remote URLs."""
    try:
        if path.is_symlink():
            raise ScanError(f"Refusing symlink: {path}")
        if path.stat().st_size > MAX_WORKFLOW_BYTES:
            raise ScanError(f"Workflow is larger than {MAX_WORKFLOW_BYTES} bytes: {path}")
        text = path.read_text(encoding="utf-8")
        doc = yaml.safe_load(text)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ScanError(f"Cannot parse {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise ScanError(f"Workflow root must be a YAML mapping: {path}")
    jobs = doc.get("jobs", {})
    if not isinstance(jobs, dict):
        raise ScanError(f"'jobs' must be a mapping in {path}")
    events = _events(doc)
    high_trust = bool(events & HIGH_TRUST_EVENTS)
    display = display_path or str(path)
    findings: list[Finding] = []
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            raise ScanError(f"Job '{job_id}' must be a mapping in {path}")
        steps = job.get("steps", [])
        if steps is None:
            steps = []
        if not isinstance(steps, list):
            raise ScanError(f"Steps of '{job_id}' must be a list in {path}")
        if any(not isinstance(step, dict) for step in steps):
            raise ScanError(f"Step in '{job_id}' must be a mapping in {path}")
        agent_steps = [step for step in steps if _has_agent(step)]
        if not agent_steps:
            continue  # This scanner is intentionally AI-agent-specific.
        privileged, reason = _job_privilege(doc, job)
        input_markers = sorted(marker for marker in UNTRUSTED_INPUTS
                               if any(_expression_contains(_flat(step), marker)
                                      for step in agent_steps))
        # A pipeline may pull PR text into an env var via an earlier step; the
        # static analysis does not currently follow those indirect variables.
        for marker in input_markers:
            if privileged and high_trust:
                findings.append(_finding(
                    "PTL001", "high", display, text, str(job_id),
                    f"AI agent reads untrusted event data with {reason}.",
                    marker,
                    "Move the AI step to a read-only, secret-free job; use an "
                    "isolated downstream job with explicitly validated safe outputs."))
            elif privileged:
                findings.append(_finding(
                    "PTL002", "medium", display, text, str(job_id),
                    f"AI agent receives event-controlled data with {reason}; verify fork restrictions.",
                    marker, "Use read-only token and remove secrets from the agent job."))
        if high_trust and privileged:
            for step in steps:
                uses = str(step.get("uses", "")).lower()
                run = str(step.get("run", "")).lower()
                ref = _flat(step.get("with", {})).lower()
                unsafe_checkout = ("actions/checkout@" in uses and
                                   any(_expression_contains(ref, marker)
                                       for marker in PR_HEAD_MARKERS))
                unsafe_shell = bool(re.search(r"\bgh\s+pr\s+checkout\b", run))
                if unsafe_checkout or unsafe_shell:
                    evidence = "actions/checkout@" if unsafe_checkout else "gh pr checkout"
                    findings.append(_finding(
                        "PTL003", "high", display, text, str(job_id),
                        "Privileged AI workflow retrieves potentially untrusted PR code.",
                        evidence, "Do not run/check out PR head in a privileged job. "
                        "Separate untrusted checks from all write tokens and secrets."))
        if high_trust and privileged and not input_markers:
            findings.append(_finding(
                "PTL004", "medium", display, text, str(job_id),
                f"AI agent runs on a public-input event with {reason}; indirect prompt flow not proven.",
                next(iter(sorted(events & HIGH_TRUST_EVENTS)), "event"),
                "Review indirect inputs, tools, and credential exposure. Use a read-only, "
                "secret-free job and approve privileged actions separately."))
        if _permission_is_write(job.get("permissions", doc.get("permissions"))):
            p = job.get("permissions", doc.get("permissions"))
            if p == "write-all" or (isinstance(p, dict) and
                                    sum(_permission_is_write(v) for v in p.values()) >= 3):
                findings.append(_finding(
                    "PTL005", "low", display, text, str(job_id),
                    "AI agent job grants broadly scoped GITHUB_TOKEN write permissions.",
                    "permissions", "Grant only the individual token scopes needed by "
                    "a separate output/publish job."))
    return sorted(set(findings), key=lambda x: (x.path, x.job, x.rule_id, x.evidence))


def scan(target: Path) -> tuple[list[Finding], int]:
    """Return (findings, workflow count); invalid inputs raise ScanError."""
    target = target.expanduser()
    if not target.exists():
        raise ScanError(f"Path not found: {target}")
    if target.is_symlink():
        raise ScanError(f"Refusing symlink: {target}")
    if target.is_file():
        candidates = [target]
        root = target.parent
    elif target.is_dir():
        root = target
        folder = target / ".github" / "workflows"
        if not folder.is_dir() or folder.is_symlink():
            raise ScanError(f"No safe .github/workflows directory: {target}")
        candidates = sorted(list(folder.glob("*.yml")) + list(folder.glob("*.yaml")))
    else:
        raise ScanError(f"Unsupported path: {target}")
    if len(candidates) > MAX_WORKFLOWS:
        raise ScanError(f"Too many workflows (>{MAX_WORKFLOWS})")
    findings: list[Finding] = []
    for item in candidates:
        if item.is_symlink() or not item.resolve().is_relative_to(root.resolve()):
            raise ScanError(f"Refusing out-of-tree workflow: {item}")
        findings.extend(analyze_workflow(item, str(item.relative_to(root))))
    return sorted(findings, key=lambda x: (x.path, x.job, x.rule_id, x.evidence)), len(candidates)

