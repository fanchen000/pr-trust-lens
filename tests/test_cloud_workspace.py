"""Small, offline guards for the public Claude Cloud entry repository."""

from __future__ import annotations

import json
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOKEN = re.compile(
    r"\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"
    r"|gh[pousr]_[A-Za-z0-9_]{25,}"
    r"|github_pat_[A-Za-z0-9_]{30,}"
    r"|AKIA[A-Z0-9]{16})\b"
)
FORBIDDEN_NAMES = {
    ".env", ".mcp.json", "auth-profiles.json", "credentials.json",
    "id_rsa", "id_ed25519", "settings.local.json",
}
FORBIDDEN_SUFFIXES = {".pem", ".key", ".p12", ".sqlite", ".sqlite3", ".db", ".jsonl"}


def tracked_files() -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
    )
    return [Path(p.decode("utf-8")) for p in proc.stdout.split(b"\0") if p]


class CloudWorkspaceSafetyTests(unittest.TestCase):
    def test_no_local_credentials_in_git(self) -> None:
        bad = [
            str(p) for p in tracked_files()
            if p.name in FORBIDDEN_NAMES
            or p.suffix.lower() in FORBIDDEN_SUFFIXES
            or any(part in {"secrets", "credentials", ".ssh"} for part in p.parts)
            or p.name.startswith(".env.")
        ]
        self.assertEqual([], bad, f"Tracked secret/local-state paths: {bad}")

    def test_no_obvious_live_tokens_in_text(self) -> None:
        bad = []
        for path in tracked_files():
            blob = (ROOT / path).read_bytes()
            if b"\0" in blob or len(blob) > 500_000:
                continue
            if TOKEN.search(blob.decode("utf-8", errors="replace")):
                bad.append(str(path))
        self.assertEqual([], bad, f"Possible hard-coded tokens in: {bad}")

    def test_claude_permissions_are_restrictive(self) -> None:
        cfg = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8"))
        rules = cfg["permissions"]
        self.assertFalse(rules.get("allow"), "Do not blanket-allow extra tools")
        for rule in (
            "Read(./.env)", "Read(./secrets/**)",
            "Bash(gh repo delete *)", "Bash(git push --force *)",
        ):
            self.assertIn(rule, rules["deny"])

    def test_github_actions_read_only(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertRegex(ci, r"(?m)^permissions:\n  contents: read$")
        self.assertNotIn("pull_request_target:", ci)
        self.assertNotIn("secrets.", ci)


if __name__ == "__main__":
    unittest.main()
