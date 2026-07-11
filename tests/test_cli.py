from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from leaklens.cli import main
from leaklens.hooks import MARKER, hook_is_executable, install_hook, uninstall_hook


class CliTests(unittest.TestCase):
    def test_scan_exit_codes_and_json_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.py"
            path.write_text('password = "Q9!wE8@rT7#y"', encoding="utf-8")  # leaklens:allow -- synthetic test fixture
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["--no-baseline", "scan", str(path), "--format", "json"])
        self.assertEqual(code, 1)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["version"], 1)
        self.assertEqual(len(payload["findings"]), 1)

    def test_clean_scan_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "safe.py"
            path.write_text("safe = True", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["scan", str(path)]), 0)

    def test_baseline_create_then_scan_suppresses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.py"
            baseline = root / "baseline.json"
            source.write_text('password = "Q9!wE8@rT7#y"', encoding="utf-8")  # leaklens:allow -- synthetic test fixture
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["baseline", "create", str(source), "--output", str(baseline)]), 0)
                code = main(["--baseline", str(baseline), "scan", str(source)])
            self.assertEqual(code, 0)

    def test_rules_json_is_machine_readable(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["rules", "--format", "json"]), 0)
        self.assertGreater(len(json.loads(output.getvalue())), 10)


class HookTests(unittest.TestCase):
    def test_installs_executable_and_only_uninstalls_managed_hook(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, stdout=subprocess.DEVNULL)
            hook = install_hook(root)
            self.assertIn(MARKER, hook.read_text(encoding="utf-8"))
            if os.name != "nt":
                self.assertTrue(hook_is_executable(hook))
            self.assertTrue(uninstall_hook(root))
            self.assertFalse(hook.exists())

    def test_refuses_to_replace_unmanaged_hook(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, stdout=subprocess.DEVNULL)
            hook = root / ".git" / "hooks" / "pre-commit"
            hook.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")
            with self.assertRaisesRegex(FileExistsError, "reviewing"):
                install_hook(root)


if __name__ == "__main__":
    unittest.main()
