"""Offline regression scenarios for the supported static trust-boundary patterns."""

import json
import tempfile
import unittest
from pathlib import Path

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

    def test_high_risk_workflow_run_pr_body(self):
        self.assertIn("PTL001", self.rules(workflow(
            event="workflow_run", prompt="${{ github.event.pull_request.body }}")))

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


if __name__ == "__main__":
    unittest.main()

