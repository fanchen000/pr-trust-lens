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
ACTION_EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}", re.DOTALL)
ENV_REF = re.compile(r"\benv\.([A-Za-z_][A-Za-z0-9_]*)\b", re.I)
STEP_REF = re.compile(
    r"\bsteps\.([A-Za-z_][A-Za-z0-9_-]*)\.outputs\.([A-Za-z_][A-Za-z0-9_-]*)\b",
    re.I,
)
OUTPUT_NAME = re.compile(r"""(?:echo\s+['"]?)([A-Za-z_][A-Za-z0-9_-]*)=""", re.I)
SHELL_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


class BoundedSafeLoader(yaml.SafeLoader):
    """Limit YAML alias expansion / nesting and reject duplicate YAML keys."""

    MAX_NODES = 10_000
    MAX_ALIASES = 100
    MAX_DEPTH = 75

    def __init__(self, stream: str):
        super().__init__(stream)
        self.nodes_seen = 0
        self.aliases_seen = 0
        self.node_depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            self.aliases_seen += 1
            if self.aliases_seen > self.MAX_ALIASES:
                raise yaml.YAMLError("too many YAML aliases")
        self.nodes_seen += 1
        if self.nodes_seen > self.MAX_NODES:
            raise yaml.YAMLError("too many YAML nodes")
        self.node_depth += 1
        try:
            if self.node_depth > self.MAX_DEPTH:
                raise yaml.YAMLError("YAML nesting is too deep")
            return super().compose_node(parent, index)
        finally:
            self.node_depth -= 1

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        if isinstance(node, yaml.MappingNode):
            seen: set[Any] = set()
            for key_node, _ in node.value:
                key = self.construct_object(key_node, deep=deep)
                try:
                    if key in seen:
                        raise yaml.YAMLError(f"duplicate YAML key: {key!r}")
                    seen.add(key)
                except TypeError as exc:
                    raise yaml.YAMLError("unhashable YAML mapping key") from exc
        return super().construct_mapping(node, deep=deep)


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


def _taint(
    value: str,
    env: dict[str, Any],
    outputs: dict[tuple[str, str], dict[str, str]],
    seen: frozenset[str] = frozenset(),
    depth: int = 0,
) -> dict[str, str]:
    """Bounded expression provenance through scoped env and known step outputs."""
    if depth > 12:
        return {}
    sources: dict[str, str] = {}
    for expression in ACTION_EXPR.findall(value):
        lowered = expression.lower()
        for marker in UNTRUSTED_INPUTS:
            if re.search(r"(?<![\w.])" + re.escape(marker) + r"(?![\w.])", lowered):
                sources[marker] = marker
        for name in ENV_REF.findall(expression):
            lookup = f"env.{name}"
            if lookup.lower() not in seen and name in env:
                refs = _taint(_flat(env[name]), env, outputs,
                              seen | {lookup.lower()}, depth + 1)
                for marker, chain in refs.items():
                    sources[marker] = f"{chain} -> {lookup}"
        for step_id, key in STEP_REF.findall(expression):
            for marker, chain in outputs.get((step_id.lower(), key.lower()), {}).items():
                sources[marker] = f"{chain} -> steps.{step_id}.outputs.{key}"
    return sources


def _step_outputs(
    step: dict[str, Any],
    env: dict[str, Any],
    outputs: dict[tuple[str, str], dict[str, str]],
) -> dict[tuple[str, str], dict[str, str]]:
    step_id = step.get("id")
    script = step.get("run")
    if not isinstance(step_id, str) or not isinstance(script, str):
        return {}
    produced: dict[tuple[str, str], dict[str, str]] = {}
    step_env = {**env, **(step.get("env") if isinstance(step.get("env"), dict) else {})}
    for line in script.splitlines():
        if "GITHUB_OUTPUT" not in line or ">>" not in line:
            continue
        named = OUTPUT_NAME.search(line)
        if not named:
            continue
        traces = _taint(line, step_env, outputs)
        # Only trace explicit variable references on the output-writing line.
        for variable in SHELL_VARIABLE.finditer(line):
            name = variable.group(1) or variable.group(2)
            if name in step_env:
                for marker, chain in _taint(_flat(step_env[name]), step_env, outputs).items():
                    traces[marker] = f"{chain} -> shell.$" + name
        if traces:
            produced[(step_id.lower(), named.group(1).lower())] = traces
    return produced


def _has_agent(step: dict[str, Any]) -> bool:
    text = _flat({"uses": step.get("uses", ""), "run": step.get("run", "")}).lower()
    return any(marker in text for marker in AGENT_MARKERS)


def _permission_is_write(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in WRITE_PERMISSIONS
    if isinstance(value, dict):
        return any(_permission_is_write(v) for v in value.values())
    return False


def _job_privilege(doc: dict[str, Any], job: dict[str, Any],
                   agent_steps: list[dict[str, Any]]) -> tuple[bool, str]:
    perms = job.get("permissions", doc.get("permissions"))
    if _permission_is_write(perms):
        return True, "write-capable GITHUB_TOKEN"
    # Do not attribute a secret in an unrelated step to the agent.
    materialized = {"workflow_env": doc.get("env", {}), "job_env": job.get("env", {}),
                    "agents": [{"env": s.get("env"), "with": s.get("with"),
                                "run": s.get("run")} for s in agent_steps]}
    if _expression_contains(_flat(materialized), "secrets."):
        return True, "secret reference in the agent or inherited environment"
    return False, "no explicit write token or secret detected"


def _line(text: str, evidence: str) -> int:
    # Best-effort line mapping: make no promise that an expression occurs once.
    needle = evidence.strip()
    for idx, line in enumerate(text.splitlines(), 1):
        if needle and needle in line:
            return idx
    return 1


def _finding(rule: str, severity: str, filename: str, text: str, job_id: str,
             message: str, evidence: str, remedy: str,
             location_hint: str | None = None) -> Finding:
    return Finding(rule, severity, filename, _line(text, location_hint or evidence), job_id,
                   message, evidence[:250], remedy)


def analyze_workflow(path: Path, display_path: str | None = None) -> list[Finding]:
    """Analyze a YAML file without evaluating scripts, expressions or remote URLs."""
    try:
        if path.is_symlink():
            raise ScanError(f"Refusing symlink: {path}")
        if path.stat().st_size > MAX_WORKFLOW_BYTES:
            raise ScanError(f"Workflow is larger than {MAX_WORKFLOW_BYTES} bytes: {path}")
        text = path.read_text(encoding="utf-8")
        doc = yaml.load(text, Loader=BoundedSafeLoader)
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
        privileged, reason = _job_privilege(doc, job, agent_steps)
        job_env = {**(doc.get("env") if isinstance(doc.get("env"), dict) else {}),
                   **(job.get("env") if isinstance(job.get("env"), dict) else {})}
        outputs: dict[tuple[str, str], dict[str, str]] = {}
        input_sources: dict[str, str] = {}
        for step in steps:
            if _has_agent(step):
                local_env = {**job_env, **(step.get("env") if isinstance(step.get("env"), dict) else {})}
                # 'if' controls whether a step runs; it is not itself a prompt.
                inputs = {"with": step.get("with"), "env": step.get("env"), "run": step.get("run")}
                for marker, chain in _taint(_flat(inputs), local_env, outputs).items():
                    input_sources[marker] = chain
            outputs.update(_step_outputs(step, job_env, outputs))
        input_markers = sorted(input_sources)
        permissions_declared = ("permissions" in job or "permissions" in doc)
        for marker in input_markers:
            if privileged and high_trust:
                findings.append(_finding(
                    "PTL001", "high", display, text, str(job_id),
                    f"AI agent reads untrusted event data with {reason}.",
                    input_sources[marker],
                    "Move the AI step to a read-only, secret-free job; use an "
                    "isolated downstream job with explicitly validated safe outputs.",
                    location_hint=marker))
            elif privileged:
                findings.append(_finding(
                    "PTL002", "medium", display, text, str(job_id),
                    f"AI agent receives event-controlled data with {reason}; verify fork restrictions.",
                    input_sources[marker], "Use read-only token and remove secrets from the agent job.",
                    location_hint=marker))
            elif high_trust and not permissions_declared:
                findings.append(_finding(
                    "PTL006", "medium", display, text, str(job_id),
                    "Untrusted event data enters an AI agent without explicit GITHUB_TOKEN permissions; effective privileges are unknown.",
                    input_sources[marker],
                    "Declare job permissions explicitly (prefer contents: read); isolate secrets and all write actions.",
                    location_hint=marker))
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

