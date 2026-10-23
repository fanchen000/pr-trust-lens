"""Offline regression scenarios for the supported static trust-boundary patterns."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pr_trust_lens.cli import main, sarif
from pr_trust_lens.scanner import ScanError, analyze_workflow, scan


def workflow(
    event="issue_comment",
    permissions="contents: write",
    prompt="${{ github.event.comment.body }}",
    agent="anthropics/claude-code-action@v1",
    checkout="",
    extra="",
):
    permission_lines = "\n      ".join(permissions.splitlines())
    return f"""name: sample
on: {event}
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      {permission_lines}
    steps:
      - uses: actions/checkout@v4
{checkout}      - name: Code review
        uses: {agent}
        with:
          prompt: "{prompt}"
{extra}"""


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.yaml = self.root / "workflow.yml"

    def findings(self, source):
        self.yaml.write_text(source, encoding="utf-8")
        return analyze_workflow(self.yaml)

    def rules(self, source):
        return {f.rule_id for f in self.findings(source)}

    def test_high_risk_issue_comment(self):
        self.assertIn("PTL001", self.rules(workflow()))

    def test_high_risk_issues_event(self):
        self.assertIn("PTL001", self.rules(workflow(
            event="issues", prompt="${{ github.event.issue.body }}")))

    def test_high_risk_target_pr_title(self):
        self.assertIn("PTL001", self.rules(workflow(
            event="pull_request_target", prompt="${{ github.event.pull_request.title }}")))

    def test_workflow_run_does_not_invent_pull_request_body(self):
        rules = self.rules(workflow(
            event="workflow_run", prompt="${{ github.event.pull_request.body }}"))
        self.assertNotIn("PTL001", rules)
        self.assertIn("PTL004", rules)

    def test_issue_comment_pr_fields_do_not_prove_direct_flow(self):
        self.assertNotIn("PTL001", self.rules(workflow(
            event="issue_comment", prompt="${{ github.event.pull_request.body }}")))

    def test_multiple_events_retain_possible_issue_source(self):
        self.assertIn("PTL001", self.rules(workflow(
            event="[push, issues]", prompt="${{ github.event.issue.body }}")))

    def test_unknown_event_keeps_conservative_signal(self):
        self.assertIn("PTL002", self.rules(workflow(
            event="future_unknown_event", prompt="${{ github.event.issue.body }}")))

    def test_read_only_agent_has_no_high_finding(self):
        self.assertNotIn("PTL001", self.rules(workflow(permissions="contents: read")))

    def test_no_agent_no_finding(self):
        src = workflow().replace(
            "anthropics/claude-code-action@v1", "actions/cache@v4")
        self.assertEqual([], self.findings(src))

    def test_safe_push_agent_no_high_finding(self):
        self.assertNotIn("PTL001", self.rules(workflow(
            event="push", prompt="Analyze code changed yesterday")))

    def test_pull_request_with_write_is_medium(self):
        self.assertIn("PTL002", self.rules(workflow(
            event="pull_request", prompt="${{ github.event.pull_request.title }}")))

    def test_secret_reference_high_finding(self):
        self.assertIn("PTL001", self.rules(workflow(
            permissions="contents: read",
            extra='        env:\n          AGENT_SECRET: "${{ secrets.AGENT_TOKEN }}"\n')))

    def test_head_checkout_privileged(self):
        checkout = """      - uses: actions/checkout@v4
        with:
          ref: "${{ github.event.pull_request.head.sha }}"
"""
        self.assertIn("PTL003", self.rules(workflow(checkout=checkout)))

    def test_head_checkout_read_only_not_high(self):
        checkout = """      - uses: actions/checkout@v4
        with:
          ref: "${{ github.event.pull_request.head.sha }}"
"""
        self.assertNotIn("PTL003", self.rules(workflow(
            permissions="contents: read", checkout=checkout)))

    def test_gh_pr_checkout(self):
        src = workflow(extra="      - name: Untrusted checkout\n        run: gh pr checkout 3\n")
        self.assertIn("PTL003", self.rules(src))

    def test_broad_permissions(self):
        src = workflow(permissions="contents: write\nissues: write\nchecks: write")
        self.assertIn("PTL005", self.rules(src))

    def test_report_indirect_risk_without_claiming_exploit(self):
        src = workflow(prompt="Please summarize the issue")
        rules = self.rules(src)
        self.assertIn("PTL004", rules)
        self.assertNotIn("PTL001", rules)

    def test_literal_marker_is_not_a_prompt_input(self):
        src = workflow(prompt="Never trust github.event.issue.body")
        self.assertNotIn("PTL001", self.rules(src))

    def test_cyclic_yaml_anchor_does_not_hang(self):
        src = """on: issue_comment
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with: &settings
          nested: *settings
"""
        self.assertEqual([], self.findings(src))

    def test_workflow_env_indirect_flow(self):
        src = """on: issue_comment
env:
  PR_TEXT: "${{ github.event.comment.body }}"
jobs:
  review:
    runs-on: ubuntu-latest
    permissions: {contents: write}
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "${{ env.PR_TEXT }}"
"""
        matches = self.findings(src)
        self.assertIn("PTL001", {x.rule_id for x in matches})
        self.assertIn("env.PR_TEXT", matches[0].evidence)
        self.assertEqual(matches[0].line, 3)

    def test_job_env_indirect_flow(self):
        src = workflow(prompt="${{ env.PR_TEXT }}")
        src = src.replace("    steps:\n", "    env:\n      PR_TEXT: '${{ github.event.issue.body }}'\n    steps:\n")
        self.assertIn("PTL001", self.rules(src))

    def test_step_env_indirect_flow(self):
        src = workflow(prompt="${{ env.PR_TEXT }}")
        src = src.replace("        with:\n", "        env:\n          PR_TEXT: '${{ github.event.comment.body }}'\n        with:\n")
        self.assertIn("PTL001", self.rules(src))

    def test_step_output_provenance(self):
        src = """on: issue_comment
jobs:
  review:
    runs-on: ubuntu-latest
    permissions: {issues: write}
    steps:
      - id: extract
        run: echo "payload=${{ github.event.comment.body }}" >> "$GITHUB_OUTPUT"
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "${{ steps.extract.outputs.payload }}"
"""
        f = self.findings(src)
        self.assertIn("PTL001", {x.rule_id for x in f})
        self.assertIn("steps.extract.outputs.payload", f[0].evidence)
        self.assertEqual(f[0].line, 8)

    def test_step_output_via_shell_env(self):
        src = """on: issues
jobs:
  review:
    runs-on: ubuntu-latest
    permissions: {issues: write}
    steps:
      - id: stage
        env:
          PAYLOAD: "${{ github.event.issue.body }}"
        run: echo "data=$PAYLOAD" >> "$GITHUB_OUTPUT"
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "${{ steps.stage.outputs.data }}"
"""
        f = self.findings(src)
        self.assertIn("PTL001", {x.rule_id for x in f})
        self.assertIn("shell.$PAYLOAD", f[0].evidence)

    def test_no_taint_from_unrelated_prior_step(self):
        src = """on: issue_comment
jobs:
  review:
    runs-on: ubuntu-latest
    permissions: {contents: write}
    steps:
      - id: extract
        run: echo "${{ github.event.comment.body }}"
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "Review code"
"""
        f = self.findings(src)
        self.assertNotIn("PTL001", {x.rule_id for x in f})
        self.assertIn("PTL004", {x.rule_id for x in f})

    def test_no_taint_from_if_expression_only(self):
        src = workflow(prompt="Code review")
        src = src.replace("        with:\n", "        if: ${{ github.event.comment.body != '' }}\n        with:\n")
        self.assertNotIn("PTL001", self.rules(src))

    def test_env_override_wins(self):
        src = """on: issue_comment
env:
  INPUT: "${{ github.event.issue.body }}"
jobs:
  review:
    runs-on: ubuntu-latest
    permissions: {contents: write}
    env:
      INPUT: "known safe text"
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "${{ env.INPUT }}"
"""
        self.assertNotIn("PTL001", self.rules(src))

    def test_unused_step_output_not_tainted(self):
        src = """on: issue_comment
jobs:
  review:
    runs-on: ubuntu-latest
    permissions: {contents: write}
    steps:
      - id: get
        run: echo "other=${{ github.event.comment.body }}" >> "$GITHUB_OUTPUT"
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "${{ steps.get.outputs.safe }}"
"""
        self.assertNotIn("PTL001", self.rules(src))

    def test_unknown_token_permission_is_not_assumed_safe(self):
        src = """on: issue_comment
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with: {prompt: "${{ github.event.comment.body }}"}
"""
        r = self.rules(src)
        self.assertIn("PTL006", r)
        self.assertNotIn("PTL001", r)

    def test_explicit_read_only_is_not_unknown(self):
        self.assertNotIn("PTL006", self.rules(workflow(permissions="contents: read")))

    def test_duplicate_top_level_permissions_rejected(self):
        with self.assertRaises(ScanError):
            self.findings("on: issues\npermissions: {contents: read}\npermissions: {contents: write}\njobs: {}\n")

    def test_duplicate_nested_permission_rejected(self):
        with self.assertRaises(ScanError):
            self.findings(workflow(permissions="contents: read\ncontents: write"))

    def test_excessive_aliases_rejected(self):
        src = "name: alias limit\nseed: &v sample\naliases:\n" + "\n".join("  - *v" for _ in range(110)) + "\njobs: {}\n"
        with self.assertRaises(ScanError):
            self.findings(src)

    def test_indirect_env_cycle_terminates(self):
        src = """on: issues
jobs:
  review:
    permissions: {contents: write}
    env:
      ONE: "${{ env.TWO }}"
      TWO: "${{ env.ONE }}"
    steps:
      - uses: anthropics/claude-code-action@v1
        with: {prompt: "${{ env.ONE }}"}
"""
        self.assertNotIn("PTL001", self.rules(src))

    def test_secret_only_in_other_step_not_agent_credentials(self):
        src = """on: issue_comment
jobs:
  review:
    permissions: {contents: read}
    steps:
      - name: unrelated
        run: echo "doing a job"
        env: {SOME_KEY: "${{ secrets.DEPLOY_KEY }}"}
      - uses: anthropics/claude-code-action@v1
        with: {prompt: "${{ github.event.comment.body }}"}
"""
        self.assertNotIn("PTL001", self.rules(src))

    def test_bad_yaml_fails_closed(self):
        with self.assertRaises(ScanError):
            self.findings("jobs: [oops\n")

    def test_non_mapping_job_fails_closed(self):
        with self.assertRaises(ScanError):
            self.findings("on: push\njobs:\n  bad: string\n")

    def test_directory_scan_and_sarif(self):
        folder = self.root / ".github" / "workflows"
        folder.mkdir(parents=True)
        (folder / "review.yml").write_text(workflow(), encoding="utf-8")
        findings, count = scan(self.root)
        self.assertEqual(count, 1)
        report = sarif(findings)
        self.assertEqual(report["version"], "2.1.0")
        self.assertEqual(report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
                         ["artifactLocation"]["uri"], ".github/workflows/review.yml")

    def test_cli_thresholds(self):
        self.yaml.write_text(workflow(), encoding="utf-8")
        self.assertEqual(main(["scan", str(self.yaml), "--fail-on", "none"]), 0)
        self.assertEqual(main(["scan", str(self.yaml), "--fail-on", "high"]), 1)

    def test_cli_bad_path(self):
        self.assertEqual(main(["scan", str(self.root / "nonexistent")]), 2)

    def test_symlink_rejected(self):
        try:
            self.yaml.symlink_to(self.root / "elsewhere")
        except OSError:
            self.skipTest("symlink creation not permitted by OS")
        with self.assertRaises(ScanError):
            scan(self.yaml)

    def test_total_repository_size_limit_fails_closed(self):
        folder = self.root / ".github" / "workflows"
        folder.mkdir(parents=True)
        (folder / "one.yml").write_text(workflow(), encoding="utf-8")
        with patch("pr_trust_lens.scanner.MAX_REPOSITORY_BYTES", 10):
            with self.assertRaisesRegex(ScanError, "total size limit"):
                scan(self.root)


if __name__ == "__main__":
    unittest.main()

