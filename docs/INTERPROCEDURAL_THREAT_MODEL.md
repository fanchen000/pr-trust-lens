# Trust boundaries in local reusable GitHub Actions workflows (v0.3.0)

This design implements a **static, bounded, evidence-based provenance graph**,
not an expression interpreter, a full shell taint analyzer, or proof of an
exploitable vulnerability. The scanner does not contact GitHub or execute a
single workflow. A file scan reports only local job rules; a repository scan
additionally analyzes explicitly linked workflows.

## Evidence chain

1. Identify a real caller job with a literal local workflow target, such as
   ./.github/workflows/check.yml.
2. Capture the originating caller event and explicit caller token permissions.
3. Trace known untrusted Actions event expressions passed via literal with:
   inputs, including bracket syntax and bounded input-through-input hops.
4. Resolve only an in-repository callee with an actual workflow_call trigger.
5. Propagate source markers through callee inputs, workflow/job/step env and
   simple earlier step outputs to the recognized AI agent's inputs.
6. Emit PTL007 only if a linked provenance trace exists and an effective write
   token, explicitly passed secret or relevant unknown token scope merits
   review. Include the caller job path and source trace in the finding.

The caller token permission acts as a ceiling: a read-only caller cannot
become write-capable because the callee requests write. No permissions
declaration means **unknown**, not proven write. A callee reference to a
secret is not counted as caller-secret exposure if the caller did not
explicitly pass/inherit secrets. Since v0.5.0, the checker also compares
the actual target secret name with the set of names explicitly passed to
the callee (or an inherited wildcard); unrelated secret names do not
prove exposure. Named secrets stay scoped across nested calls.

Since v0.6.0, the caller GITHUB_TOKEN write ceiling is represented as a
set of granted **named write scopes** (or unknown). At every linked call,
explicit requested scopes are intersected with the current ceiling.
Write-all preserves the upstream ceiling but never elevates a narrow one;
an omitted permissions key preserves known inherited scopes, whereas an
undeclared ancestor default is unknown. The built-in
secrets.GITHUB_TOKEN is not counted as another, unconstrained credential.

The scanner also checks known GitHub event payload paths against their
declared trigger. A push-only event does not provide PR body data. For
unrecognized event types it deliberately retains the source as uncertain
instead of treating unfamiliar schemas as safe. These are static source
checks, not evaluation of workflow if-guards or event authenticity.

## Scope and performance limits

- Only literal relative local targets are followed. No cloning/fetching of
  external actions or workflows; missing or unsafe local targets fail closed.
- At most 8 linked levels and 200 traversed call edges per scan. Cycles
  fail closed, and symlinks/overlarge or malformed YAML are rejected.
- YAML aliases, nesting, node count and duplicate keys are bounded/rejected.
  LibYAML acceleration is used when available, but a safe loader remains
  mandatory; there is no object deserialization.
- No dynamic expressions, job authorization checks, guard conditions,
  artifact content, shell pipelines, output multiline blocks, external
  reusable workflow calls or current repository settings are analyzed.
- A locally identified caller route is not evidence that an unknown
  external adversary can trigger it. A workflow_call file without
  a known caller does not acquire an invented public trigger.
- The scanner deliberately emits **potential-risk signals for review**.
  False positives and false negatives remain possible.

Relevant GitHub documentation:
[reuse workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows),
[contexts](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts),
[secure GitHub Actions](https://github.blog/security/supply-chain-security/four-tips-to-keep-your-github-actions-workflows-secure/).
