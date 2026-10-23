# Using PR Trust Lens in your GitHub Actions workflow

## Recommended minimal configuration

PR Trust Lens is intentionally **offline at scan time**: it never reads a
GitHub token, fetches external workflow source, launches an AI agent or
executes the workflow being audited. Installing dependencies via pip still
requires package-index access unless dependencies were preinstalled or cached.

Place the following YAML in your repository's own workflows directory:

~~~yaml
name: PR Trust Lens
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
      - uses: fanchen000/pr-trust-lens@v0.5.0
        with:
          path: .
          format: github
          fail-on: high
~~~

**Pin the PR Trust Lens action to the full 40-character SHA of its tested
v0.5.0 release in production.** Moving tags are less robust than immutable
commit pins. Do not give the audit workflow an API key or write token.

The scanner reads the repository-root workflow directory or a single
workflow file. It does not execute user-supplied scripts; by default only a
HIGH risk signal fails CI. Change the threshold to medium or low only after
reviewing your findings. Use none for nonblocking discovery.

## CLI and code-scanning SARIF

The CLI prints valid SARIF 2.1.0 when called with:

    python -m pr_trust_lens scan . --format sarif --fail-on none > trust-lens.sarif

SARIF results include a rule ID, sanitized repository-relative file URI,
best-effort source line, rule catalog description and versioned partial
fingerprint. This enables comparison of repeat findings across runs but
does not prove vulnerability identity. Use your existing code-scanning
upload pipeline if your GitHub plan enables the feature; enabling SARIF
upload requires additional workflow permissions in the upload job only.
PR Trust Lens's default composite action does **not** request them.

GitHub inline annotations are available with:

    python -m pr_trust_lens scan . --format github --fail-on high

They use official GitHub runner error, warning and notice command syntax;
untrusted strings are escaped to prevent forged commands from scanned YAML.

## Security and supply-chain notes

- Use a commit SHA for third-party actions and keep checkout credentials
  disabled where no Git operation requires them.
- The composite action uses your runner's Python interpreter and pip.
  Dependency resolution happens at the runner's configured index, not
  within our scanner. For tightly restricted supply chains, preinstall
  a verified release wheel and PyYAML from your own artifact mirror.
- Runtime scanner scans only local workflow YAML, never external callers.
  There is no cloud telemetry, hosted dependency, license check or
  model/API call.
- Human-readable and GitHub-command output must never let workflow names
  inject a separate control line. Please report any exception to this
  safety property as a security issue.

The project's own [public CI](../.github/workflows/ci.yml) invokes the
composite action with the same minimal inputs as downstream users.
