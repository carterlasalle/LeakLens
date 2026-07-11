from __future__ import annotations

import unittest

from leaklens.models import Severity, fingerprint, redact


class ModelTests(unittest.TestCase):
    def test_fingerprint_is_stable_and_domain_separated(self) -> None:
        self.assertEqual(fingerprint("a-rule", "value"), fingerprint("a-rule", "value"))
        self.assertNotEqual(fingerprint("a-rule", "value"), fingerprint("other-rule", "value"))
        self.assertNotIn("value", fingerprint("a-rule", "value"))

    def test_redaction_never_returns_the_full_secret(self) -> None:
        self.assertEqual(redact("short"), "•••••")
        self.assertEqual(redact("abcdefghijklmnop"), "abc…nop")

    def test_severity_parser_is_actionable(self) -> None:
        self.assertEqual(Severity.parse("HIGH"), Severity.HIGH)
        with self.assertRaisesRegex(ValueError, "choose from"):
            Severity.parse("urgent")


if __name__ == "__main__":
    unittest.main()
