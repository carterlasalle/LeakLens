from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from leaklens.baseline import Baseline, BaselineError, load_baseline, save_baseline
from leaklens.config import ConfigError, load_config
from leaklens.engine import Scanner
from leaklens.models import Severity


class ConfigTests(unittest.TestCase):
    def test_loads_scan_options_and_custom_rule(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".leaklens.toml"
            path.write_text(
                """
[scan]
minimum_severity = "high"
max_file_size = 2048
exclude = ["fixtures/**"]

[[rules]]
id = "acme-token"
title = "Acme token"
pattern = "(?P<secret>acme_[A-Za-z0-9]{16})"
severity = "critical"
tags = ["acme", "token"]
""",
                encoding="utf-8",
            )
            config = load_config(path)
        self.assertEqual(config.minimum_severity, Severity.HIGH)
        self.assertIn("fixtures/**", config.excludes)
        self.assertEqual(config.custom_rules[0].id, "acme-token")

    def test_rejects_custom_rule_without_secret_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.toml"
            path.write_text('[[rules]]\nid="bad-rule"\npattern="abc"\n', encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "must define"):
                load_config(path)


class BaselineTests(unittest.TestCase):
    def test_round_trips_fingerprints_without_secrets(self) -> None:
        result = Scanner().scan_text('password = "Q9!wE8@rT7#y"')
        baseline = Baseline.from_findings(result.findings)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            save_baseline(path, baseline)
            raw = path.read_text(encoding="utf-8")
            loaded = load_baseline(path)
        self.assertNotIn("Q9!wE8", raw)
        self.assertEqual(loaded.fingerprints, baseline.fingerprints)

    def test_rejects_unknown_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            path.write_text(json.dumps({"schema_version": 99}), encoding="utf-8")
            with self.assertRaisesRegex(BaselineError, "schema"):
                load_baseline(path)


if __name__ == "__main__":
    unittest.main()

