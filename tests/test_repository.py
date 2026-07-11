from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from leaklens.engine import Scanner
from leaklens.filesystem import FileScanner
from leaklens.repository import RepositoryScanner


class RepositoryScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self._git("init", "-b", "main")
        self._git("config", "user.name", "LeakLens Test")
        self._git("config", "user.email", "test@example.invalid")
        scanner = Scanner()
        self.repository = RepositoryScanner(self.root, scanner, FileScanner(scanner))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_scans_tracked_and_untracked_worktree_files(self) -> None:
        (self.root / "tracked.py").write_text('password = "Q9!wE8@rT7#y"', encoding="utf-8")
        self._git("add", "tracked.py")
        self._git("commit", "-m", "base")
        (self.root / "new.py").write_text('api_key = "Z8@xC7!vB6#n"', encoding="utf-8")
        result = self.repository.scan_worktree()
        self.assertEqual({finding.location.path for finding in result.findings}, {str(self.root / "tracked.py"), str(self.root / "new.py")})

    def test_staged_scan_reports_only_added_lines_at_real_line_number(self) -> None:
        (self.root / "app.py").write_text("safe = True\n", encoding="utf-8")
        self._git("add", "app.py")
        self._git("commit", "-m", "base")
        (self.root / "app.py").write_text('safe = True\npassword = "Q9!wE8@rT7#y"\n', encoding="utf-8")
        self._git("add", "app.py")
        result = self.repository.scan_staged()
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].location.line, 2)
        self.assertEqual(result.findings[0].location.path, "app.py")

    def test_history_reports_first_commit_for_repeated_secret(self) -> None:
        (self.root / "old.py").write_text('password = "Q9!wE8@rT7#y"\n', encoding="utf-8")
        self._git("add", "old.py")
        self._git("commit", "-m", "leak")
        first = self._git("rev-parse", "HEAD").strip()
        (self.root / "old.py").write_text('password = "Q9!wE8@rT7#y"\nother = 1\n', encoding="utf-8")
        self._git("add", "old.py")
        self._git("commit", "-m", "unrelated")
        result = self.repository.scan_history()
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].location.commit, first)

    def _git(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout


if __name__ == "__main__":
    unittest.main()
