from __future__ import annotations

import unittest

from leaklens.engine import Scanner
from leaklens.models import Severity


class EngineTests(unittest.TestCase):
    def test_detects_structured_tokens_and_never_serializes_raw_value(self) -> None:
        token = "ghp_" + "A1b2" * 10
        result = Scanner().scan_text(f'TOKEN = "{token}"\n', path="config.py")
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.rule_id, "github-pat")
        self.assertEqual((finding.location.line, finding.location.column), (1, 10))
        self.assertNotIn(token, repr(finding))
        self.assertNotIn(token, str(finding.to_dict()))

    def test_detects_database_password_and_prioritizes_it(self) -> None:
        text = 'DATABASE_URL="postgresql://admin:C0mpl3x-Pass@db.internal/app"\n'  # leaklens:allow -- synthetic test fixture
        finding = Scanner().scan_text(text).findings[0]
        self.assertEqual(finding.rule_id, "database-url")
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_generic_detector_rejects_placeholders(self) -> None:
        result = Scanner().scan_text('api_key = "your_api_key"')
        self.assertEqual(result.findings, [])
        self.assertEqual(result.stats.findings_suppressed, 1)

    def test_inline_and_previous_line_allow_comments_suppress(self) -> None:
        first = Scanner().scan_text('password = "C0mpl3x-not-real"  # leaklens:allow\n')
        second = Scanner().scan_text(
            '# leaklens:allow -- documented fixture\npassword = "C0mpl3x-not-real"\n'
        )
        third = Scanner().scan_text(
            'password = "C0mpl3x-not-real"\n# leaklens:allow -- formatted call\n'
        )
        self.assertFalse(first.findings)
        self.assertFalse(second.findings)
        self.assertFalse(third.findings)

    def test_baseline_fingerprint_suppresses_exact_finding(self) -> None:
        text = 'secret = "aB3!cD4@eF5#"'  # leaklens:allow -- synthetic test fixture
        initial = Scanner().scan_text(text)
        fingerprint = initial.findings[0].fingerprint
        suppressed = Scanner(allowed_fingerprints=frozenset({fingerprint})).scan_text(text)
        self.assertFalse(suppressed.findings)

    def test_minimum_severity_filters_rules_before_matching(self) -> None:
        text = 'api_key = "aB3!cD4@eF5#"'  # leaklens:allow -- synthetic test fixture
        result = Scanner(minimum_severity=Severity.CRITICAL).scan_text(text)
        self.assertFalse(result.findings)

    def test_finding_limit_stops_unbounded_result_growth(self) -> None:
        text = "\n".join(
            f'password = "A{i:04d}!bB2@cC3#d"' for i in range(100)
        )  # leaklens:allow -- synthetic test fixture
        result = Scanner(max_findings=7).scan_text(text)
        self.assertEqual(len(result.findings), 7)
        self.assertIn("finding limit 7", result.errors[0])


if __name__ == "__main__":
    unittest.main()
