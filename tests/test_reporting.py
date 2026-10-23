"""Stable user-facing reports, safe runner annotations and real action metadata."""

from contextlib import redirect_stdout
from dataclasses import replace
from io import StringIO
from pathlib import Path
import json
import re
import tempfile
import unittest

import yaml

from pr_trust_lens.cli import fingerprint, github_annotations, main, sarif
from pr_trust_lens.scanner import Finding


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.finding = Finding(
            rule_id="PTL007", severity="high", path=".github/workflows/a.yml",
            line=12, job="review", message="Caller-sourced data reaches AI agent",
            evidence="github.event.comment.body -> inputs.question",
            remediation="Remove the write token",
        )

    def test_deterministic_sarif_metadata_and_fingerprint(self):
        report = sarif([self.finding])
        result = report["runs"][0]["results"][0]
        self.assertEqual(report["version"], "2.1.0")
        self.assertEqual(result["ruleId"], "PTL007")
        self.assertEqual(result["partialFingerprints"]["pr-trust-lens/v1"],
                         fingerprint(self.finding))
        self.assertEqual(report["runs"][0]["tool"]["driver"]["rules"][0]["id"], "PTL007")
        self.assertEqual(report["runs"][0]["tool"]["driver"]["rules"][0]
                         ["shortDescription"]["text"],
                         "Local reusable-workflow AI-agent trust crossing")
        self.assertIn("security", report["runs"][0]["tool"]["driver"]
                      ["rules"][0]["properties"]["tags"])
        self.assertEqual(sarif([self.finding]), report)

    def test_fingerprint_ignores_line_number_but_not_evidence(self):
        changed_line = replace(self.finding, line=999)
        changed_input = replace(self.finding, evidence="github.event.issue.body")
        self.assertEqual(fingerprint(self.finding), fingerprint(changed_line))
        self.assertNotEqual(fingerprint(self.finding), fingerprint(changed_input))

    def test_runner_annotations_escape_untrusted_control_characters(self):
        hostile = replace(
            self.finding,
            path=".github/workflows/bad:name,part.yml",
            message="safe%message\n::set-output name=unsafe::yes",
            evidence="data\r\n::error::impostor",
            job="job\n::warning::fake",
        )
        command = github_annotations([hostile])[0]
        self.assertTrue(command.startswith("::error file=.github/workflows/bad%3Aname%2Cpart.yml,"))
        self.assertEqual(command.count("\n"), 0)
        self.assertEqual(command.count("\r"), 0)
        self.assertIn("%25", command)
        self.assertIn("%0A", command)
        self.assertIn("%0D", command)
        self.assertIn("title=PR Trust Lens PTL007::", command)
        self.assertEqual(len(github_annotations([hostile])), 1)

    def test_severity_to_command_mapping(self):
        mapped = [
            replace(self.finding, severity="high"),
            replace(self.finding, severity="medium"),
            replace(self.finding, severity="low"),
        ]
        messages = github_annotations(mapped)
        self.assertEqual([msg.split(" ", 1)[0] for msg in messages],
                         ["::error", "::warning", "::notice"])

    def test_human_format_cannot_emit_forged_command_via_job_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "adversarial.yml"
            file.write_text("""on: issue_comment
jobs:
  "safe\\n::error::forged-annotation":
    permissions: {contents: write}
    steps:
      - uses: anthropics/claude-code-action@v1
        with: {prompt: "${{ github.event.comment.body }}"}
""", encoding="utf-8")
            out = StringIO()
            with redirect_stdout(out):
                status = main(["scan", str(file), "--format", "human"])
            self.assertEqual(status, 1)
            self.assertNotIn("\n::error::", out.getvalue())
            self.assertIn(r"\n::error::forged-annotation", out.getvalue())

    def test_input_error_log_is_one_line_even_with_newline_in_path(self):
        from contextlib import redirect_stderr
        with tempfile.TemporaryDirectory() as tmp:
            out = StringIO()
            with redirect_stderr(out):
                status = main(["scan", str(Path(tmp) / "no\n::error::forged")])
            self.assertEqual(status, 2)
            self.assertEqual(out.getvalue().count("\n"), 1)

    def test_actual_cli_outputs_pure_annotations(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "unsafe.yml"
            file.write_text("""on: issues
jobs:
  review:
    permissions: {contents: write}
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "${{ github.event.issue.body }}"
""", encoding="utf-8")
            out = StringIO()
            with redirect_stdout(out):
                result = main(["scan", str(file), "--format", "github", "--fail-on", "none"])
            self.assertEqual(result, 0)
            self.assertTrue(out.getvalue().startswith("::error file="))
            self.assertNotIn("PR Trust Lens: scanned", out.getvalue())

    def test_action_metadata_is_composite_and_does_not_interpolate_shell(self):
        path = Path(__file__).resolve().parents[1] / "action.yml"
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.assertEqual(doc["runs"]["using"], "composite")
        self.assertEqual(set(doc["inputs"]), {"path", "fail-on", "format"})
        steps = doc["runs"]["steps"]
        self.assertEqual(steps[0]["shell"], "bash")
        self.assertIn("$GITHUB_ACTION_PATH", steps[0]["run"])
        self.assertEqual(steps[1]["shell"], "bash")
        self.assertIn('"$PTL_SCAN_PATH"', steps[1]["run"])
        self.assertIn('"$PTL_FAIL_ON"', steps[1]["run"])
        self.assertIn('"$PTL_FORMAT"', steps[1]["run"])
        self.assertNotIn("${{", steps[1]["run"])
        self.assertTrue(all(k in steps[1]["env"] for k in
                            ("PTL_SCAN_PATH", "PTL_FAIL_ON", "PTL_FORMAT")))

    def test_ci_runs_composite_action(self):
        path = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        matrix = doc["jobs"]["test"]["strategy"]["matrix"]["python-version"]
        self.assertEqual(matrix, ["3.10", "3.12", "3.13"])
        self.assertIn("./", [step.get("uses") for step in
                             doc["jobs"]["test"]["steps"]])


if __name__ == "__main__":
    unittest.main()
