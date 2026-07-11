from __future__ import annotations

import json
import unittest

from leaklens.engine import Scanner
from leaklens.render import render, render_sarif
from leaklens.rules import builtin_rules


class RenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = "ghp_" + "A1b2" * 10
        self.result = Scanner().scan_text(f'TOKEN="{self.secret}"', path="app.py")

    def test_every_format_redacts_raw_secret(self) -> None:
        for format_name in ("table", "json", "jsonl", "csv", "sarif"):
            with self.subTest(format_name=format_name):
                output = render(self.result, format_name, builtin_rules())
                self.assertNotIn(self.secret, output)

    def test_sarif_contains_location_rule_and_partial_fingerprint(self) -> None:
        sarif = render_sarif(self.result, builtin_rules())
        serialized = json.dumps(sarif)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("github-pat", serialized)
        self.assertIn("leakLensSecretFingerprint/v1", serialized)
        self.assertIn("app.py", serialized)

    def test_clean_table_is_clear(self) -> None:
        clean = Scanner().scan_text("safe = True")
        self.assertIn("No secrets found", render(clean, "table", builtin_rules()))


if __name__ == "__main__":
    unittest.main()
