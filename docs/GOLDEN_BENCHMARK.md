# Synthetic golden accuracy benchmark

This is an explicitly curated, **non-independent synthetic corpus** to make
PR Trust Lens's supported threat claims stable across updates. It should
never be reported as an estimate of real-world accuracy, precision, recall,
vulnerability confirmation or ecosystem adoption.

The individual source files live in
[tests/fixtures/golden](../tests/fixtures/golden/) and the hand-written
expected (rule ID, severity) pairs live in
[tests/test_golden.py](../tests/test_golden.py).

| Scenario | Expected supported result |
|---|---|
| Direct issue comment, write token, AI-agent prompt | PTL001 / HIGH |
| Same issue comment, explicit read-only job | No finding |
| Public issue prompt, token permissions undeclared | PTL006 / MEDIUM |
| Privileged non-agent workflow | No finding |
| A dangerous-looking string literal in an Actions expression | PTL004 / MEDIUM advisory, **not** PTL001 |
| Orphan local reusable workflow, no proven caller | No direct caller finding |
| PR expression on an unrelated event with write token | PTL002 / MEDIUM, not asserted public reachability |
| AI-agent job with 3 write scopes and no dangerous prompt | PTL005 / LOW |

Reproduce using:

    python -m unittest tests.test_golden -v

The same cases also run in the project's CI matrix. This contract
prevents a new release from silently increasing severity or duplicating
findings for these exact fixtures.

The larger [pinned-source validation](EXTERNAL_VALIDATION_2026-10-22.md)
checks compatibility with real repositories but has not undergone manual
true-positive labeling. A credible claim of real precision or recall would
require independently triaged findings, sampling, and independently known
false negatives. No such claim is currently made.
