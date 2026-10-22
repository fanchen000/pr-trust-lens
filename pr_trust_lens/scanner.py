"""Safe, deterministic and deliberately conservative GitHub Actions analysis."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

MAX_WORKFLOW_BYTES = 2_000_000
MAX_WORKFLOWS = 1_000
MAX_LINKED_CALLS = 200
MAX_LINK_DEPTH = 8

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
ROOT_REF = re.compile(r"(?:github|env|steps|inputs|secrets)\b", re.I)
DOT_REF = re.compile(r"\.([A-Za-z_][A-Za-z0-9_-]*)")
BRACKET_REF = re.compile(r"""\[\s*(['"])([A-Za-z_][A-Za-z0-9_-]*)\1\s*\]""")
# Supported subset of the GITHUB_OUTPUT protocol: a single echo assignment
# redirected to the real output file, not a comment / unrelated command.
OUTPUT_WRITE = re.compile(
    r"""^\s*echo\s+(?P<quote>['"])(?P<name>[A-Za-z_][A-Za-z0-9_-]*)=(?P<value>.*?)"""
    r"""(?P=quote)\s*>>\s*["']?\$(?:GITHUB_OUTPUT|\{GITHUB_OUTPUT\})["']?\s*(?:#.*)?$"""
)
SHELL_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


class BoundedSafeLoader(getattr(yaml, "CSafeLoader", yaml.SafeLoader)):
    """Use a safe loader with strict duplicate-key rejection.

    Token/depth limits are enforced by _check_yaml_limits before construction,
    including when accelerated libyaml is available.
    """

    MAX_NODES = 10_000
    MAX_ALIASES = 100
    MAX_DEPTH = 75

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


def _check_yaml_limits(text: str) -> None:
    """Count real YAML tokens before safe object construction, without aliases
    being expanded. C-backed scanning keeps large generated workflows practical.
    """
    depth = 0
    nodes = 0
    aliases = 0
    starts = (yaml.BlockMappingStartToken, yaml.BlockSequenceStartToken,
              yaml.FlowMappingStartToken, yaml.FlowSequenceStartToken)
    ends = (yaml.BlockEndToken, yaml.FlowMappingEndToken, yaml.FlowSequenceEndToken)
    for token in yaml.scan(text, Loader=BoundedSafeLoader):
        if isinstance(token, yaml.AliasToken):
            aliases += 1
            if aliases > BoundedSafeLoader.MAX_ALIASES:
                raise yaml.YAMLError("too many YAML aliases")
        if isinstance(token, starts):
            depth += 1
            if depth > BoundedSafeLoader.MAX_DEPTH:
                raise yaml.YAMLError("YAML nesting is too deep")
        elif isinstance(token, ends):
            depth -= 1
        if isinstance(token, (*starts, yaml.ScalarToken, yaml.AliasToken)):
            nodes += 1
            if nodes > BoundedSafeLoader.MAX_NODES:
                raise yaml.YAMLError("too many YAML nodes")


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


@dataclass(frozen=True)
class CallContext:
    """One actual local caller route; never inferred from external workflows."""

    events: frozenset[str]
    inputs: dict[str, dict[str, str]]
    token_cap: str  # write, read, or unknown; nested calls cannot elevate
    allows_secrets: bool
    via: str


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
    return any(
        ref.lower() == needle.lower() or (
            needle.endswith(".") and ref.lower().startswith(needle.lower()))
        for expression in ACTION_EXPR.findall(value)
        for ref in _expression_refs(expression)
    )


def _expression_refs(expression: str) -> list[str]:
    """Lex supported Actions context paths, never executing expressions.

    GitHub supports both dot and literal bracket selectors. Quoted string
    *values* are skipped so format('github.event.comment.body') is not a
    source, while github['event']['comment']['body'] remains a source.
    Dynamic selectors are intentionally not resolved.
    """
    refs: list[str] = []
    pos = 0
    while pos < len(expression):
        if expression[pos] in ("'", '"'):
            quote = expression[pos]
            pos += 1
            while pos < len(expression):
                if expression[pos] == quote:
                    pos += 1
                    if pos < len(expression) and expression[pos] == quote:
                        pos += 1
                        continue
                    break
                pos += 1
            continue
        root = ROOT_REF.match(expression, pos)
        if root and (pos == 0 or not (
            expression[pos - 1].isalnum() or expression[pos - 1] in "_."
        )):
            parts = [root.group(0)]
            end = root.end()
            while True:
                dot = DOT_REF.match(expression, end)
                bracket = BRACKET_REF.match(expression, end)
                match = dot or bracket
                if not match:
                    break
                parts.append(dot.group(1) if dot else bracket.group(2))
                end = match.end()
            if len(parts) > 1:
                refs.append(".".join(parts))
            pos = end
        else:
            pos += 1
    return refs


def _taint(
    value: str,
    env: dict[str, Any],
    outputs: dict[tuple[str, str], dict[str, str]],
    seen: frozenset[str] = frozenset(),
    depth: int = 0,
    inputs: dict[str, dict[str, str]] | None = None,
) -> dict[str, str]:
    """Bounded expression provenance through scoped env and known step outputs."""
    if depth > 12:
        return {}
    sources: dict[str, str] = {}
    for expression in ACTION_EXPR.findall(value):
        for ref in _expression_refs(expression):
            canonical = ref.lower()
            if canonical in UNTRUSTED_INPUTS:
                sources[canonical] = ref
            parts = canonical.split(".")
            if len(parts) == 2 and parts[0] == "env":
                key_name = ref.split(".")[1]
                key = next((k for k in env if k == key_name), None)
                if canonical not in seen and key is not None:
                    nested = _taint(_flat(env[key]), env, outputs,
                                    seen | {canonical}, depth + 1, inputs)
                    for marker, chain in nested.items():
                        sources[marker] = f"{chain} -> {ref}"
            if len(parts) == 4 and parts[0] == "steps" and parts[2] == "outputs":
                for marker, chain in outputs.get((parts[1], parts[3]), {}).items():
                    sources[marker] = f"{chain} -> {ref}"
            if len(parts) == 2 and parts[0] == "inputs" and inputs:
                for marker, chain in inputs.get(parts[1], {}).items():
                    sources[marker] = f"{chain} -> {ref}"
    return sources


def _step_outputs(
    step: dict[str, Any],
    env: dict[str, Any],
    outputs: dict[tuple[str, str], dict[str, str]],
    inputs: dict[str, dict[str, str]] | None = None,
) -> dict[tuple[str, str], dict[str, str]]:
    step_id = step.get("id")
    script = step.get("run")
    if not isinstance(step_id, str) or not isinstance(script, str):
        return {}
    produced: dict[tuple[str, str], dict[str, str]] = {}
    step_env = {**env, **(step.get("env") if isinstance(step.get("env"), dict) else {})}
    for line in script.splitlines():
        named = OUTPUT_WRITE.match(line)
        if named is None:
            continue
        value = named.group("value")
        traces = _taint(value, step_env, outputs, inputs=inputs)
        # Only trace explicit variable references on the output-writing line.
        if named.group("quote") == '"':
            for variable in SHELL_VARIABLE.finditer(value):
                name = variable.group(1) or variable.group(2)
                if name in step_env:
                    for marker, chain in _taint(_flat(step_env[name]), step_env, outputs,
                                               inputs=inputs).items():
                        traces[marker] = f"{chain} -> shell.$" + name
        if traces:
            produced[(step_id.lower(), named.group("name").lower())] = traces
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


def _token_cap(doc: dict[str, Any], job: dict[str, Any],
               inherited: str = "write") -> str:
    """Conservatively model GitHub reusable-workflow token permission ceilings."""
    perms = job.get("permissions", doc.get("permissions"))
    if inherited == "read":
        return "read"
    if perms is not None and not _permission_is_write(perms):
        return "read"
    if inherited == "unknown" or perms is None:
        return "unknown"
    return "write"


def _line(text: str, evidence: str) -> int:
    # Best-effort line mapping: make no promise that an expression occurs once.
    needle = evidence.strip()
    for idx, line in enumerate(text.splitlines(), 1):
        if needle and needle in line:
            return idx
        # Bracket syntax should point at the actual expression, not line 1.
        if needle and any(
            ref.lower() == needle.lower()
            for expr in ACTION_EXPR.findall(line)
            for ref in _expression_refs(expr)
        ):
            return idx
    return 1


def _finding(rule: str, severity: str, filename: str, text: str, job_id: str,
             message: str, evidence: str, remedy: str,
             location_hint: str | None = None) -> Finding:
    return Finding(rule, severity, filename, _line(text, location_hint or evidence), job_id,
                   message, evidence[:250], remedy)


def _load_workflow(path: Path) -> tuple[str, dict[str, Any]]:
    """Fail closed for invalid local documents before graph analysis."""
    try:
        if path.is_symlink():
            raise ScanError(f"Refusing symlink: {path}")
        if path.stat().st_size > MAX_WORKFLOW_BYTES:
            raise ScanError(f"Workflow is larger than {MAX_WORKFLOW_BYTES} bytes: {path}")
        text = path.read_text(encoding="utf-8")
        _check_yaml_limits(text)
        doc = yaml.load(text, Loader=BoundedSafeLoader)
    except (OSError, UnicodeError, yaml.YAMLError, RecursionError) as exc:
        raise ScanError(f"Cannot parse {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise ScanError(f"Workflow root must be a YAML mapping: {path}")
    if not isinstance(doc.get("jobs", {}), dict):
        raise ScanError(f"'jobs' must be a mapping in {path}")
    return text, doc


def analyze_workflow(path: Path, display_path: str | None = None,
                     *, context: CallContext | None = None,
                     loaded: tuple[str, dict[str, Any]] | None = None) -> list[Finding]:
    """Analyze a YAML file without evaluating scripts, expressions or remote URLs."""
    text, doc = loaded if loaded is not None else _load_workflow(path)
    jobs = doc.get("jobs", {})
    if not isinstance(jobs, dict):
        raise ScanError(f"'jobs' must be a mapping in {path}")
    events = set(context.events) if context else _events(doc)
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
        effective = (_token_cap(doc, job, context.token_cap) if context else
                     _token_cap(doc, job, "unknown"))
        if context:
            inherited_env = {"workflow_env": doc.get("env", {}), "job_env": job.get("env", {}),
                             "agents": [{"env": s.get("env"), "with": s.get("with"),
                                         "run": s.get("run")} for s in agent_steps]}
            has_secret = context.allows_secrets and _expression_contains(
                _flat(inherited_env), "secrets."
            )
            privileged = effective == "write" or has_secret
            reason = ("write-capable inherited GITHUB_TOKEN" if effective == "write" else
                      "caller-passed secret reference" if has_secret else
                      "effective token permissions unknown" if effective == "unknown" else
                      "read-only inherited GITHUB_TOKEN")
        job_env = {**(doc.get("env") if isinstance(doc.get("env"), dict) else {}),
                   **(job.get("env") if isinstance(job.get("env"), dict) else {})}
        outputs: dict[tuple[str, str], dict[str, str]] = {}
        input_sources: dict[str, str] = {}
        for step in steps:
            if _has_agent(step):
                local_env = {**job_env, **(step.get("env") if isinstance(step.get("env"), dict) else {})}
                # 'if' controls whether a step runs; it is not itself a prompt.
                inputs = {"with": step.get("with"), "env": step.get("env"), "run": step.get("run")}
                for marker, chain in _taint(_flat(inputs), local_env, outputs,
                                            inputs=context.inputs if context else None).items():
                    input_sources[marker] = chain
            outputs.update(_step_outputs(step, job_env, outputs,
                                         inputs=context.inputs if context else None))
        input_markers = sorted(input_sources)
        permissions_declared = ("permissions" in job or "permissions" in doc)
        for marker in input_markers:
            if context:
                if not privileged and (effective != "unknown" or not high_trust):
                    continue
                severity = ("high" if privileged and high_trust else "medium")
                hint = re.search(r"inputs\.[A-Za-z_][A-Za-z0-9_-]*",
                                 input_sources[marker])
                findings.append(_finding(
                    "PTL007", severity, display, text,
                    f"{context.via} -> {job_id}",
                    f"Local reusable workflow: traced caller-controlled data reaches an AI agent with {reason}; caller guards not evaluated.",
                    f"{context.via}: {input_sources[marker]}",
                    "Validate caller trust and inputs, explicitly minimize caller and callee token permissions; separate agent from privileged writes.",
                    location_hint=hint.group(0) if hint else marker))
            elif privileged and high_trust:
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
        if (not context or effective == "write") and _permission_is_write(
                job.get("permissions", doc.get("permissions"))):
            p = job.get("permissions", doc.get("permissions"))
            if p == "write-all" or (isinstance(p, dict) and
                                    sum(_permission_is_write(v) for v in p.values()) >= 3):
                findings.append(_finding(
                    "PTL005", "low", display, text, str(job_id),
                    "AI agent job grants broadly scoped GITHUB_TOKEN write permissions.",
                    "permissions", "Grant only the individual token scopes needed by "
                    "a separate output/publish job."))
    return sorted(set(findings), key=lambda x: (x.path, x.job, x.rule_id, x.evidence))


LOCAL_WORKFLOW = re.compile(r"^\./\.github/workflows/([A-Za-z0-9_.-]+\.ya?ml)$")


def _linked_findings(
    files: dict[str, Path],
    loaded: dict[str, tuple[str, dict[str, Any]]],
) -> list[Finding]:
    """Walk only pinned-in-tree local workflow edges, never remote 'uses'."""
    documents = {name: artifact[1] for name, artifact in loaded.items()}
    results: list[Finding] = []
    calls_seen = 0

    def visit(name: str, ctx: CallContext | None,
              ancestry: tuple[str, ...]) -> None:
        nonlocal calls_seen
        if len(ancestry) >= MAX_LINK_DEPTH:
            raise ScanError(f"Local workflow call depth exceeds {MAX_LINK_DEPTH}: {name}")
        source = documents[name]
        jobs = source.get("jobs", {})
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                raise ScanError(f"Job '{job_id}' must be a mapping in {files[name]}")
            uses = job.get("uses")
            if not isinstance(uses, str) or not uses.startswith("./.github/workflows/"):
                continue
            match = LOCAL_WORKFLOW.fullmatch(uses)
            if not match:
                raise ScanError(f"Invalid local workflow reference in {name}: {uses}")
            callee = match.group(1)
            if callee not in files:
                raise ScanError(f"Local workflow target missing: {uses}")
            if "workflow_call" not in _events(documents[callee]):
                raise ScanError(f"Local workflow missing 'on: workflow_call': {callee}")
            if callee in ancestry or callee == name:
                raise ScanError(f"Local reusable workflow cycle: {' -> '.join(ancestry + (name, callee))}")
            calls_seen += 1
            if calls_seen > MAX_LINKED_CALLS:
                raise ScanError(f"Local workflow calls exceed {MAX_LINKED_CALLS}")
            origin = set(ctx.events) if ctx else _events(source)
            in_values = job.get("with") or {}
            if not isinstance(in_values, dict):
                raise ScanError(f"Invalid caller inputs in {name}:{job_id}")
            passed: dict[str, dict[str, str]] = {}
            for key, value in in_values.items():
                if isinstance(key, str):
                    traced = _taint(_flat(value), {}, {}, inputs=ctx.inputs if ctx else None)
                    if traced:
                        passed[key.lower()] = {
                            marker: f"{trace} -> {name}:{job_id}.with.{key}"
                            for marker, trace in traced.items()
                        }
            secrets = job.get("secrets")
            allows_secrets = (
                bool(secrets) and (ctx is None or ctx.allows_secrets)
            )
            inherited = ctx.token_cap if ctx else "write"
            cap = _token_cap(source, job, inherited)
            route = f"{ctx.via} -> {name}:{job_id}" if ctx else f"{name}:{job_id}"
            linked = CallContext(frozenset(origin), passed, cap, allows_secrets, route)
            results.extend(analyze_workflow(files[callee],
                                            f".github/workflows/{callee}",
                                            context=linked,
                                            loaded=loaded[callee]))
            visit(callee, linked, ancestry + (name,))

    for source_name in sorted(files):
        # No implicit invocation on workflow_call-only entrypoints. Their
        # actual caller may live outside this repo and is deliberately unknown.
        if _events(documents[source_name]) != {"workflow_call"}:
            visit(source_name, None, ())
    return results


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
    loaded: dict[str, tuple[str, dict[str, Any]]] = {}
    for item in candidates:
        if item.is_symlink() or not item.resolve().is_relative_to(root.resolve()):
            raise ScanError(f"Refusing out-of-tree workflow: {item}")
        document = _load_workflow(item)
        loaded[item.name] = document
        findings.extend(analyze_workflow(item, str(item.relative_to(root)), loaded=document))
    if target.is_dir():
        findings.extend(_linked_findings({item.name: item for item in candidates}, loaded))
    return sorted(set(findings), key=lambda x: (x.path, x.job, x.rule_id, x.evidence)), len(candidates)

