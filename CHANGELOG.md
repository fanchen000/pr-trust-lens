# Changelog

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

