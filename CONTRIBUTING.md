# Contributing

Thank you for helping make AI-assisted open-source maintenance safer.

1. Open an issue with a reproducible example and the expected risk assessment.
2. Keep changes narrowly scoped and add a positive and negative synthetic YAML test.
3. Run: python -m unittest discover -s tests -v
4. Explain false positives/negatives and the proposed severity.
5. Submit a pull request. Never include secrets, private project text or real tokens.

The maintainers prefer clear, evidence-based feedback and backward-compatible
changes to output field names. CLI and SARIF stability are goals, not yet guarantees.

