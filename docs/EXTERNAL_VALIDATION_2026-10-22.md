# Public-source validation, 2026-10-22

This is a **maintainer-run evaluation on public source code**, not evidence of
third-party adoption, an external contribution, or a confirmed vulnerability.
Inputs were read-only clones pinned to immutable public Git commit IDs. We did
not execute any workflow, use any secrets, contact maintainers with untriaged
security allegations, or store repository source in PR Trust Lens.

## Setup and reproduction

Using PR Trust Lens v0.2.0 and Python 3.10+:

1. Clone each upstream from the list below into a separate temporary folder.
2. Check out its exact Git commit ID.
3. Install PR Trust Lens and run the following command on that clone:

    python -m pr_trust_lens scan PATH_TO_CLONE --format json --fail-on none

4. Inspect each finding's workflow, trigger, permissions, job and actual agent
   inputs to establish whether there is a credible security issue.

| Public upstream | Inspected commit | Workflow files | PTL002 | PTL004 | PTL005 | Findings |
|---|---|---:|---:|---:|---:|---:|
| [anthropics/claude-code-action](https://github.com/anthropics/claude-code-action) | 6b6870e649b5ff408753befeaee5fc7989d4e6a9 | 14 | 0 | 2 | 1 | 3 |
| [google-github-actions/run-gemini-cli](https://github.com/google-github-actions/run-gemini-cli) | 387c8ddb7a72078825da941758b811b9153c71e8 | 11 | 16 | 0 | 4 | 20 |
| **Total** | | **25** | **16** | **2** | **5** | **23** |

These counts are for **static signals** and do not incorporate manual
investigation of trust checks or the surrounding ecosystem. In particular,
PTL002 in a workflow_call-based setup is not proof that a public attacker can
actually invoke that workflow. PTL004 explicitly says that the indirect prompt
dataflow has **not** been proven. PTL005 flags broad write scopes, not misuse.

## Meaningful evaluation and limits

This run verifies that the CLI parses non-synthetic third-party workflows,
identifies supported actions and produces file-and-rule-specific results
without code execution. It also reveals an actionable research gap: the engine
cannot follow all reusable-workflow caller/callee trust relationships.

The maintainer's two local clone operations are **one evaluation effort**,
not 25 users, 23 vulnerabilities, or any external adoption.

Security triage should follow GitHub's responsible disclosure procedures if a
separate investigation eventually substantiates a vulnerability.

