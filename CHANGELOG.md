# Changelog

## 0.5.0 (2026-10-23)

- **Reduce impossible-source warnings**: compare event payload source paths
  with the declared trigger (e.g. a push event does not carry PR body).
  For unrecognized/custom event types, the scanner remains conservative
  and does not assert the source is absent. Multi-trigger workflows retain
  any compatible source path.
- **Track explicitly passed secret identities across local workflow calls**:
  a named secret exposed to the callee does not imply other secret names
  are available. Support inherited and renamed secrets across nested calls,
  without implicitly exposing names absent from the caller's scope.
- Improve effective token ceiling propagation: an undeclared caller default
  is **unknown**, an explicit read-only caller remains read-only, and an
  explicit write-capable caller remains potentially writable when a callee
  does not reduce its token permissions.
- Expand offline regression coverage to 88 unit tests and 10 independent
  synthetic golden cases; run pinned public-source compatibility scans.
- No claim of verified exploitability, independent adoption or real-world
  precision/recall. The scanner still does not interpret job authorization
  guards, dynamic payloads or unrecognized event schemas.

## 0.4.0 (2026-10-23)

- Release a **GitHub composite action**, dogfooded in public CI on Python
  3.10, 3.12 and 3.13, without requiring users to copy the scanner source.
- Support `--format github` with native GitHub error/warning/notice
  annotations. Escape workflow-command properties and data correctly.
  Sanitize adversarial control characters in human output and CLI errors.
- Emit stable versioned SARIF partial fingerprints and fixed rule titles so
  code-scanning consumers can correlate repeat findings across runs.
- **Precision fix:** do not invent a caller context for an orphan
  `workflow_call` entrypoint. Retain PTL007 for proven local caller routes.
  A pinned run-gemini-cli snapshot drops 16 duplicate PTL002 signals while
  retaining 16 caller-path PTL007 signals. Neither count is a vulnerability claim.
- Introduce a synthetic golden accuracy corpus with explicit positive and
  negative expectations, plus runner-command injection regression tests.
- Add a 128 MB aggregate workflow-input guard to bound repository scans.
- Keep offline execution, zero API tokens and no remote downloads at runtime.

## 0.3.0 (2026-10-22)

- Add **PTL007**: bounded source-to-sink provenance across explicitly local
  reusable GitHub Actions workflows. Trace actual caller inputs, preserve
  caller event context and respect read-only GITHUB_TOKEN permission ceilings.
  Do not assume external or orphan workflow_call entrypoints are exploitable.
- Recognize literal dot and bracket Actions context selectors; exclude
  reference-like strings inside quoted expression literals.
- Harden step-output tracking: only a narrow documented echo assignment to
  GITHUB_OUTPUT is followed; single-quoted shell variables and comments do
  not falsely propagate taint.
- Use accelerated safe YAML parsing when available, **without losing** duplicate
  key, alias count, nesting and node limits (bounded token preflight).
- Parse each file once per repository scan, including linked analysis.
- Expand synthetic regression suite to 64 tests including deep, cyclic,
  unknown-permission, secret-policy, bracket and negative counterexamples.
- Exercise three pinned public OSS inputs; these are maintainer-run static
  evaluation findings, **not confirmed vulnerabilities or external adoption**.

## 0.2.0 (2026-10-22)

- Track directly referenced environment variables through workflow/job/step scope
  and selected explicit previous step outputs into coding-agent inputs.
- Differentiate unknown default GITHUB_TOKEN permissions with new PTL006 medium
  finding instead of silently assuming a read-only credential.
- Reject ambiguous duplicate YAML keys and cap nested nodes and aliases.
- Avoid treating event expressions in an agent step's condition as prompt data.
- Expand offline regression suite and Python compatibility CI matrix.
- Dataflow propagation is intentionally bounded: **this is not a shell interpreter
  or a complete taint engine**. See README for measured limits.

## 0.1.0 (2026-10-22)

- First source release: offline workflow scanning, five deterministic rule types,
  human/JSON/SARIF reporting, CI thresholds and synthetic regression tests.
- This first release has **no asserted third-party usage or adoption**.

