"""Small curated synthetic benchmark; not independently labeled field data."""

import json
import unittest
from pathlib import Path

from pr_trust_lens.scanner import analyze_workflow


# Expected exact rule AND severity. These labels are hand-curated from
# documented trust cases, not imported from scanner output.
GOLDEN = {
    "direct-privileged.yml": [("PTL001", "high")],
    "read-only.yml": [],
    "read-only-github-token.yml": [],
    "unknown-permissions.yml": [("PTL006", "medium")],
    "non-agent.yml": [],
    "quoted-marker.yml": [("PTL004", "medium")],
    "orphan-reusable.yml": [],
    "other-event.yml": [("PTL002", "medium")],
    "broad-write.yml": [("PTL005", "low")],
    "mismatched-push-payload.yml": [],
    "mismatched-comment-payload.yml": [("PTL004", "medium")],
}


class GoldenCorpusTests(unittest.TestCase):
    def test_curated_golden_cases(self):
        folder = Path(__file__).parent / "fixtures" / "golden"
        actual_files = {p.name for p in folder.glob("*.yml")}
        self.assertEqual(actual_files, set(GOLDEN))
        for name, expected in GOLDEN.items():
            with self.subTest(case=name):
                result = analyze_workflow(folder / name)
                actual = sorted((f.rule_id, f.severity) for f in result)
                self.assertEqual(actual, sorted(expected))
                self.assertTrue(all(f.line > 0 for f in result))
                self.assertTrue(all(f.evidence for f in result))

    def test_corpus_has_both_positive_and_negative_cases(self):
        self.assertGreaterEqual(sum(bool(labels) for labels in GOLDEN.values()), 4)
        self.assertGreaterEqual(sum(not labels for labels in GOLDEN.values()), 3)


if __name__ == "__main__":
    unittest.main()
