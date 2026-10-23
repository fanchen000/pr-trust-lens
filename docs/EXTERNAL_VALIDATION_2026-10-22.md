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

## v0.3.0 expanded technical regression (maintainer-run)

The earlier table is the actual v0.2.0 baseline and is intentionally
preserved, not rewritten as if the old release detected PTL007.

With v0.3.0, re-scanning the two previously pinned clones and adding the
public [github/gh-aw](https://github.com/github/gh-aw) source snapshot at
commit ab6db5d0e25aef034b81b5e847d59fcf14a8bf89 produced:

| Public input | Workflow files | PTL002 | PTL004 | PTL005 | PTL007 | Total signals |
|---|---:|---:|---:|---:|---:|---:|
| anthropics/claude-code-action | 14 | 0 | 2 | 1 | 0 | 3 |
| google-github-actions/run-gemini-cli | 11 | 16 | 0 | 8 | 16 | 40 |
| github/gh-aw | 387 | 0 | 37 | 224 | 0 | 261 |
| **Total** | **412** | **16** | **39** | **233** | **16** | **304** |

PTL007 is a **new caller-to-callee dataflow signal**, not proof that any of
these projects is insecure or that its defenses are bypassable. Overlapping
PTL002 and PTL007 on a single workflow do not mean independent vulnerabilities.
Most gh-aw results were low-severity, broad-write-scope PTL005 heuristics;
the tool has **not** reviewed whether those permissions are justified. There
are no measured true-positive precision/recall percentages for these
third-party inputs, because no expert ground truth was established.

### Bounded performance observation

The new preflight-limited safe C YAML loader, where available, plus parsing
once per file completed a directory scan of all 387 checked-out gh-aw
workflows in **22.44 seconds on the maintainer's Windows Python 3.12 host**.
A representative 325,032-byte generated workflow took approximately
0.119 seconds with this implementation. Numbers are local observations,
not hardware-independent throughput guarantees or a CI service-level claim.

Independent users and contributors in this evaluation: **zero verified**.

## v0.4.0 duplicate-caller finding correction

The same pinned 11-workflow google-github-actions/run-gemini-cli snapshot
now yields 16 PTL007 linked-call source traces and 8 broad-permission
PTL005 signals: **24 signals instead of 40**. The 16 removed PTL002
entries were unsupported assumptions about stand-alone workflow_call
entrypoints, duplicating PTL007 across known local callers.

This is a measured removal of unsupported, duplicate findings in this
particular public snapshot. It is **not** a claim that the remaining
signals represent exploitable flaws, nor a independently validated
false-positive-rate improvement. The previously published v0.2.0/v0.3.0
snapshot results are preserved above rather than silently rewritten.

