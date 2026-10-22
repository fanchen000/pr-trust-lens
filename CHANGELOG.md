# Changelog

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

