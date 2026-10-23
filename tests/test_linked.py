"""Cross-workflow trust and syntax counterexamples using only local fixtures."""

import tempfile
import unittest
from pathlib import Path

from pr_trust_lens.scanner import ScanError, analyze_workflow, scan


AGENT = "anthropics/claude-code-action@v1"


class LinkedWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.folder = self.root / ".github" / "workflows"
        self.folder.mkdir(parents=True)

    def add(self, name, content):
        path = self.folder / name
        path.write_text(content, encoding="utf-8")
        return path

    def caller(self, event="issue_comment", permission="contents: write",
               supplied="${{ github.event.comment.body }}",
               destination="agent.yml", secrets=""):
        return f"""on: {event}
permissions:
  {permission}
jobs:
  delegate:
    uses: ./.github/workflows/{destination}
    with:
      question: "{supplied}"
{secrets}"""

    def callee(self, permission="contents: write", expr="${{ inputs.question }}"):
        return f"""on:
  workflow_call:
    inputs:
      question:
        type: string
jobs:
  agent:
    permissions:
      {permission}
    runs-on: ubuntu-latest
    steps:
      - uses: {AGENT}
        with:
          prompt: "{expr}"
"""

    def findings(self):
        return scan(self.root)[0]

    def test_high_local_call_with_evidence(self):
        self.add("trigger.yml", self.caller())
        self.add("agent.yml", self.callee())
        f = [x for x in self.findings() if x.rule_id == "PTL007"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "high")
        self.assertIn("trigger.yml:delegate", f[0].evidence)
        self.assertIn("inputs.question", f[0].evidence)
        self.assertEqual(f[0].path, ".github/workflows/agent.yml")
        self.assertGreater(f[0].line, 1)

    def test_read_only_caller_prevents_high_finding(self):
        self.add("trigger.yml", self.caller(permission="contents: read"))
        self.add("agent.yml", self.callee(permission="contents: write"))
        self.assertNotIn("PTL007", {x.rule_id for x in self.findings()})

    def test_read_only_callee_prevents_high_finding(self):
        self.add("trigger.yml", self.caller())
        self.add("agent.yml", self.callee(permission="contents: read"))
        self.assertNotIn("PTL007", {x.rule_id for x in self.findings()})

    def test_unknown_caller_permission_is_medium_not_high(self):
        self.add("trigger.yml", """on: issue_comment
jobs:
  delegate:
    uses: ./.github/workflows/agent.yml
    with: {question: "${{ github.event.comment.body }}"}
""")
        self.add("agent.yml", self.callee())
        linked = [x for x in self.findings() if x.rule_id == "PTL007"]
        self.assertEqual([(f.severity) for f in linked], ["medium"])

    def test_untrusted_caller_input_is_not_synthesized(self):
        self.add("trigger.yml", self.caller(supplied="static safe text"))
        self.add("agent.yml", self.callee())
        self.assertNotIn("PTL007", {x.rule_id for x in self.findings()})

    def test_remote_reusable_workflow_not_fetched(self):
        self.add("trigger.yml", """on: issue_comment
jobs:
  delegate:
    uses: someone/other/.github/workflows/agent.yml@v1
    with: {question: "${{ github.event.comment.body }}"}
""")
        self.assertEqual(self.findings(), [])

    def test_orphan_workflow_call_is_unknown_not_high(self):
        self.add("agent.yml", self.callee())
        self.assertNotIn("PTL007", {x.rule_id for x in self.findings()})

    def test_orphan_reusable_workflow_must_not_invent_caller_event(self):
        self.add("agent.yml", """on: workflow_call
jobs:
  agent:
    permissions: {contents: write}
    steps:
      - uses: anthropics/claude-code-action@v1
        with: {prompt: "${{ github.event.comment.body }}"}
""")
        self.assertNotIn("PTL002", {f.rule_id for f in self.findings()})

    def test_explicit_local_caller_traces_without_double_report(self):
        self.add("trigger.yml", self.caller())
        self.add("agent.yml", """on: workflow_call
jobs:
  agent:
    permissions: {contents: write}
    steps:
      - uses: anthropics/claude-code-action@v1
        with: {prompt: "${{ github.event.comment.body }}"}
""")
        rules = {f.rule_id for f in self.findings()}
        self.assertIn("PTL007", rules)
        self.assertNotIn("PTL002", rules)

    def test_mixed_push_and_workflow_call_still_has_direct_signal(self):
        path = self.add("mixed.yml", """on: [push, workflow_call]
jobs:
  agent:
    permissions: {contents: write}
    steps:
      - uses: anthropics/claude-code-action@v1
        with: {prompt: "${{ github.event.pull_request.body }}"}
""")
        self.assertIn("PTL002", {f.rule_id for f in analyze_workflow(path)})

    def test_nested_two_hop_path(self):
        self.add("trigger.yml", self.caller(destination="middle.yml"))
        self.add("middle.yml", """on:
  workflow_call:
    inputs: {question: {type: string}}
permissions: {contents: write}
jobs:
  delegate:
    uses: ./.github/workflows/agent.yml
    permissions: {contents: write}
    with: {question: "${{ inputs.question }}"}
""")
        self.add("agent.yml", self.callee())
        evidence = [x.evidence for x in self.findings() if x.rule_id == "PTL007"]
        self.assertEqual(len(evidence), 1)
        self.assertIn("middle.yml:delegate", evidence[0])
        self.assertIn("trigger.yml:delegate", evidence[0])

    def test_non_privileged_event_is_medium(self):
        self.add("trigger.yml", self.caller(event="push", supplied="${{ github.event.comment.body }}"))
        self.add("agent.yml", self.callee())
        linked = [x for x in self.findings() if x.rule_id == "PTL007"]
        self.assertEqual([f.severity for f in linked], ["medium"])

    def test_cross_workflow_inputs_via_env(self):
        self.add("trigger.yml", self.caller())
        self.add("agent.yml", """on: workflow_call
env:
  FROM_CALLER: "${{ inputs.question }}"
jobs:
  agent:
    permissions: {contents: write}
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "${{ env.FROM_CALLER }}"
""")
        self.assertIn("PTL007", {x.rule_id for x in self.findings()})

    def test_invalid_local_reference_fails_closed(self):
        self.add("trigger.yml", self.caller(destination="../../escape.yml"))
        with self.assertRaises(ScanError):
            self.findings()

    def test_missing_local_reference_fails_closed(self):
        self.add("trigger.yml", self.caller(destination="missing.yml"))
        with self.assertRaises(ScanError):
            self.findings()

    def test_local_workflow_cycle_fails_closed(self):
        self.add("trigger.yml", self.caller(destination="middle.yml"))
        self.add("middle.yml", """on: workflow_call
jobs:
  next:
    uses: ./.github/workflows/trigger.yml
""")
        with self.assertRaises(ScanError):
            self.findings()

    def test_bracket_syntax_and_literal_not_confused(self):
        f = self.add("agent.yml", """on: issue_comment
jobs:
  agent:
    permissions: {contents: write}
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "${{ github['event']['comment']['body'] }}"
""")
        self.assertIn("PTL001", {x.rule_id for x in analyze_workflow(f)})

    def test_quoted_marker_is_not_a_source(self):
        f = self.add("agent.yml", """on: issue_comment
jobs:
  agent:
    permissions: {contents: write}
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "${{ format('github.event.comment.body') }}"
""")
        self.assertNotIn("PTL001", {x.rule_id for x in analyze_workflow(f)})

    def test_bracket_env_and_output_syntax(self):
        f = self.add("agent.yml", """on: issues
env:
  MESSAGE: "${{ github['event']['issue']['body'] }}"
jobs:
  agent:
    permissions: {contents: write}
    steps:
      - id: stage
        run: echo "payload=${{ env['MESSAGE'] }}" >> "$GITHUB_OUTPUT"
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "${{ steps['stage'].outputs['payload'] }}"
""")
        self.assertIn("PTL001", {x.rule_id for x in analyze_workflow(f)})

    def test_dynamic_bracket_index_is_not_claimed_proven(self):
        f = self.add("agent.yml", """on: issue_comment
jobs:
  agent:
    permissions: {contents: write}
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "${{ github.event[vars.PROPERTY] }}"
""")
        self.assertNotIn("PTL001", {x.rule_id for x in analyze_workflow(f)})

    def test_output_comment_does_not_create_flow(self):
        f = self.add("agent.yml", """on: issue_comment
jobs:
  agent:
    permissions: {contents: write}
    steps:
      - id: stage
        run: |
          echo "payload=safe" >> "$GITHUB_OUTPUT" # ${{ github.event.comment.body }}
      - uses: anthropics/claude-code-action@v1
        with: {prompt: "${{ steps.stage.outputs.payload }}"}
""")
        self.assertNotIn("PTL001", {x.rule_id for x in analyze_workflow(f)})

    def test_unrelated_echo_redirection_not_output(self):
        f = self.add("agent.yml", """on: issue_comment
jobs:
  agent:
    permissions: {contents: write}
    steps:
      - id: stage
        run: echo "payload=${{ github.event.comment.body }}" >> /tmp/report
      - uses: anthropics/claude-code-action@v1
        with: {prompt: "${{ steps.stage.outputs.payload }}"}
""")
        self.assertNotIn("PTL001", {x.rule_id for x in analyze_workflow(f)})

    def test_literal_single_quoted_shell_variable_not_expanded(self):
        f = self.add("agent.yml", """on: issue_comment
jobs:
  agent:
    permissions: {contents: write}
    steps:
      - id: stage
        env: {PROMPT: "${{ github.event.comment.body }}"}
        run: echo 'payload=$PROMPT' >> "$GITHUB_OUTPUT"
      - uses: anthropics/claude-code-action@v1
        with: {prompt: "${{ steps.stage.outputs.payload }}"}
""")
        self.assertNotIn("PTL001", {x.rule_id for x in analyze_workflow(f)})

    def test_secret_passed_with_readonly_token_is_privileged(self):
        self.add("trigger.yml", self.caller(
            permission="contents: read", secrets="    secrets: inherit\n"))
        self.add("agent.yml", """on: workflow_call
jobs:
  agent:
    permissions: {contents: read}
    steps:
      - uses: anthropics/claude-code-action@v1
        env: {KEY: "${{ secrets.ACCESS_TOKEN }}"}
        with: {prompt: "${{ inputs.question }}"}
""")
        linked = [x for x in self.findings() if x.rule_id == "PTL007"]
        self.assertEqual([x.severity for x in linked], ["high"])

    def test_secret_not_passed_does_not_invent_exposure(self):
        self.add("trigger.yml", self.caller(permission="contents: read"))
        self.add("agent.yml", """on: workflow_call
jobs:
  agent:
    permissions: {contents: read}
    steps:
      - uses: anthropics/claude-code-action@v1
        env: {KEY: "${{ secrets.ACCESS_TOKEN }}"}
        with: {prompt: "${{ inputs.question }}"}
""")
        self.assertNotIn("PTL007", {x.rule_id for x in self.findings()})

    def test_bracket_workflow_call_input(self):
        self.add("trigger.yml", self.caller(supplied="${{ github['event']['comment']['body'] }}"))
        self.add("agent.yml", self.callee(expr="${{ inputs['question'] }}"))
        linked = [x for x in self.findings() if x.rule_id == "PTL007"]
        self.assertEqual(len(linked), 1)
        self.assertGreater(linked[0].line, 1)

    def test_excessive_nesting_rejected_by_fast_safe_loader(self):
        source = "name: nesting\nseed: " + "[" * 90 + "1" + "]" * 90 + "\njobs: {}\n"
        path = self.add("deep.yml", source)
        with self.assertRaises(ScanError):
            analyze_workflow(path)

    def test_excessive_nodes_rejected_by_fast_safe_loader(self):
        source = "name: nodes\nvalues:\n" + "".join(f"  - item_{i}\n" for i in range(10050)) + "jobs: {}\n"
        path = self.add("many.yml", source)
        with self.assertRaises(ScanError):
            analyze_workflow(path)

    def test_yaml_python_object_tags_are_rejected(self):
        path = self.add("tag.yml", "name: !!python/object/apply:os.system ['echo forbidden']\njobs: {}\n")
        with self.assertRaises(ScanError):
            analyze_workflow(path)


if __name__ == "__main__":
    unittest.main()
