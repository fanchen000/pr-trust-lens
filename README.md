# PR Trust Lens

[![Tests](https://github.com/fanchen000/pr-trust-lens/actions/workflows/ci.yml/badge.svg)](https://github.com/fanchen000/pr-trust-lens/actions/workflows/ci.yml)

**An explainable, offline trust-boundary scanner for AI coding agents in GitHub Actions.**

PR Trust Lens asks a narrow security question: *does a GitHub Actions job let a coding agent consume attacker-controlled PR or issue content while that job has write-capable tokens or secrets?*

It prints a traceable finding, a workflow/line reference and a suggested separation of privileges. The scanner needs **no API keys, network, paid model, or repository permissions**. It never runs the code or Actions workflows it scans.

> **Status:** v0.6.0, early-stage release. Static heuristic checks only; not a complete security audit, runtime sandbox, vulnerability proof, or security guarantee. Contributions, reproducible counterexamples and false-positive reports are welcome.

## Why this exists

Coding agents are increasingly embedded in PR review, issue triage and release automation. Prompt injection becomes especially serious when untrusted text and privileged execution share one job. Recent GitInject research and Microsoft's documented Claude Code Action case show why secure task boundaries matter in practice. GitHub explicitly recommends separating untrusted fork code from privileged tokens.

PR Trust Lens is **not** a generic replacement for [zizmor](https://github.com/zizmorcore/zizmor), [actionlint](https://github.com/rhysd/actionlint), CodeQL or the OpenSSF Scorecard. They already do substantial general workflow/security analysis. Our focused extra lens is to identify a joint pattern involving **AI-agent invocation + untrusted GitHub event expressions + job privileges**, and to explain that trust path in familiar CI terms.

## Install and run

**Minimal GitHub Actions integration** (requires no secret or privileged token):

```yaml
name: AI workflow trust check
on: [push, pull_request]
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - uses: fanchen000/pr-trust-lens@v0.6.0 # replace tag with 40-char SHA for production
        with:
          path: .
          fail-on: high
          format: github
```

The composite action executes locally in the runner and produces inline
GitHub annotations. It performs dependency installation via pip, so your
runner needs PyPI connectivity during setup; **the scanner itself operates
offline**. No GitHub token or OpenAI API key is required. See
[CI integration and supply-chain guidance](docs/INTEGRATION.md).

Python 3.10+ and pip:

    git clone https://github.com/fanchen000/pr-trust-lens.git
    cd pr-trust-lens
    python -m pip install -e .
    pr-trust-lens scan examples/unsafe-ai-pr.yml

Or without installing the CLI script, after installing dependencies:

    python -m pr_trust_lens scan examples/unsafe-ai-pr.yml --format json --fail-on none
    python -m pr_trust_lens scan examples/safer-ai-pr.yml --fail-on high
    python -m pr_trust_lens scan . --format sarif --fail-on none

Scan a target repository root with a .github/workflows directory, or an individual .yml/.yaml file. The scanner only reads local files. It explicitly rejects symlinks, overlarge workflows and malformed YAML instead of silently treating them as clean.

The unsafe example produces a **PTL001 / HIGH** warning for an AI agent reading an untrusted issue-comment expression in a write-capable job. The safer example produces no supported findings. **No findings** means only that these limited rules did not match.

## What it detects

| Rule | Severity | Specific condition |
| --- | --- | --- |
| PTL001 | HIGH | Recognized AI agent consumes an untrusted event expression during a high-trust GitHub event, and the job has a write-capable token or secret reference. |
| PTL002 | MEDIUM | Recognized agent consumes an event-controlled expression and its job has privileged credentials in another event context. |
| PTL003 | HIGH | Privileged agent workflow on a high-trust event checks out PR head or runs gh pr checkout. |
| PTL004 | MEDIUM | AI agent on a public-input high-trust event has privileged credentials; direct prompt dataflow not demonstrated. |
| PTL005 | LOW | Recognized agent job has broad write permission scopes. |
| PTL006 | MEDIUM | Untrusted event data enters an agent job whose default GITHUB_TOKEN permissions were not explicitly declared; this is **unknown scope**, not proof of write access. |
| PTL007 | HIGH / MEDIUM | A **local reusable workflow call** passes an event-controlled expression through an explicit input into a recognized AI agent; impact is classified using the originating event, provable caller/callee token ceiling and explicitly passed secrets. **No remote callers are inferred.** |

Beginning in v0.2.0, the scanner follows direct GitHub expressions through
workflow/job/step environment variables and simple earlier shell steps that explicitly
write output variables. Findings carry a compact source-to-sink trace; they do not
assert that the content is an exploit.

In v0.3.0, dot and literal bracket context references are recognized, and
repository scans also follow **bounded local** reusable-workflow calls, including
two-hop cases. Only explicit in-repository call sites are modeled; a standalone
scan of one YAML file cannot establish callers. See our
[interprocedural threat model](docs/INTERPROCEDURAL_THREAT_MODEL.md) for the
trust ceiling, input assumptions and known blind spots.

In v0.5.0, event-source compatibility excludes provably mismatched fields
(for example, issue text on a push-only trigger). Local reusable-workflow
analysis also tracks **which named secrets were passed**, not merely whether
some secrets might exist. Unknown event shapes and token defaults remain
unknown rather than being assumed safe.

In v0.6.0, cross-workflow token permission ceilings are tracked per
individual scope rather than as one coarse write/read bit, following
GitHub's rule that nested reusable workflows cannot elevate the
caller's permissions. A read-only built-in GITHUB_TOKEN is not treated
as an unrelated high-privilege secret. This is a static approximation,
not runtime token introspection.

Built-in agent signals include recognizable invocations of Codex, Claude Code Action/CLI, Gemini CLI, OpenCode and GitHub Agentic Workflows. Missing or renamed patterns will be missed. A step is identified by its action name or command; mere mention of an agent in a documentation string is not sufficient.

Every finding exposes a **rule ID, severity, relative file path, best-effort line, job, evidence and remediation**. Direct event-source detection requires a GitHub Actions expression, not a bare reference inside an unrelated string.

### For CI

    python -m pip install -e .
    pr-trust-lens scan . --fail-on high

Exit codes: 0 = no findings meeting the threshold; 1 = one or more findings meeting the threshold; 2 = parse/path/input error. Use --fail-on none for discovery mode, or low/medium/high to enforce a policy. SARIF 2.1.0 output (`--format sarif`) includes stable per-finding fingerprints for code-scanning consumers. For inline GitHub annotations, use `--format github`; it emits runner commands with escaped untrusted text, not a generic log.

Our own CI is least-privilege and runs on every PR. We intentionally do not publish comments back into PRs automatically.

## Threat model and limitations

**In scope:** a repository maintainer wants an offline review of the static permissions and prompt dataflow of selected GitHub Actions AI-agent jobs. The workflow YAML is treated as untrusted input and parsed with a bounded, safe PyYAML loader (C-accelerated when available). No templates, shell scripts or actions are executed.

**Out of scope:** proving exploitation; exhaustively following shell variables, artifacts, third-party actions or remote/external reusable workflows; discovering hidden default GitHub permissions from repository settings; runtime token access; secrets exposure across containers; prompt-injection detection in model responses; remote workflow downloads; identifying every coding agent. Dataflow across arbitrary shell commands, branch conditions, multi-line output syntax, composite actions and artifact uploads is **not supported**. Conditional guards and authorization checks are not evaluated. Standalone `workflow_call` files **do not** establish public attacker reachability, and their caller-unverified prompt patterns are not escalated as PTL002. Some indirect dataflows are **not detected** and legitimate intended uses may trigger warnings. Results are conservative signals for review, not a correctness or security certification.

Recommended controls, beyond this tool: isolate untrusted inputs from secrets, grant minimum explicit GITHUB_TOKEN permissions, pin third-party actions, prevent untrusted PR code execution in privileged contexts, and require human approval or validated safe outputs for high-impact actions. Run a general-purpose Actions security scanner alongside this tool.

## Development

    python -m pip install -e .
    python -m unittest discover -s tests -v
    python -m pr_trust_lens scan examples/unsafe-ai-pr.yml --fail-on none

All tests use local synthetic workflows and no accounts or credentials. Security reports: see [SECURITY.md](SECURITY.md). Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md).

We maintain a [small explicitly labeled synthetic golden benchmark](docs/GOLDEN_BENCHMARK.md).
Passing it is evidence of regression prevention on the fixtures, **not a
real-world precision/recall score**.

See our [pinned public-source validation](docs/EXTERNAL_VALIDATION_2026-10-22.md)
and [honest community/adoption accounting](docs/COMMUNITY_AND_ADOPTION.md).
These public-source scans are our own evaluation, **not evidence that the
repositories use PR Trust Lens**.

## Research and primary documentation

- [GitInject: Real-World Prompt Injection Attacks in AI-Powered CI/CD Pipelines (June 2026)](https://arxiv.org/abs/2606.09935)
- [Microsoft Security: Securing CI/CD in an agentic world, Claude Code GitHub Action case (June 2026)](https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case/)
- [GitHub: Securely using pull_request_target](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [GitHub Agentic Workflows security design](https://docs.github.com/en/copilot/concepts/agent-capabilities/agent-powered-workflows-and-operations/about-github-agentic-workflows)
- [OWASP GitHub Actions Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html)

The references provide context, not endorsement or a claim that the scanner implements all recommended safeguards.

## License

MIT. See [LICENSE](LICENSE).

