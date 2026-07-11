from __future__ import annotations

import unittest

from leaklens.engine import Scanner


class DetectorCatalogTests(unittest.TestCase):
    def test_every_builtin_detector_has_a_positive_fixture(self) -> None:
        fixtures = {
            "private-key": "-----BEGIN " + "PRIVATE KEY-----",
            "github-pat": "ghp_" + "A1b2" * 10,
            "gitlab-pat": "glpat-" + "A1b2C3d4" * 3,
            "aws-access-key": "AKIA" + "A1B2C3D4E5F6G7H8",
            "google-api-key": "AIza" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"[:35],
            "slack-token": "xoxb-" + "1234567890-" * 3 + "AbCdEfGhIj",
            "stripe-live-key": "sk_" + "live_" + "A1b2C3d4E5f6G7h8I9j0K1",
            "openai-api-key": "sk-" + "A1b2C3d4_E5f6G7h8-I9j0K1l2",
            "anthropic-api-key": "sk-ant-" + "A1b2C3d4_E5f6G7h8-I9j0K1l2",
            "sendgrid-api-key": "SG."
            + "A1b2C3d4E5f6G7h8"
            + "."
            + "I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4",
            "npm-access-token": "npm_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"[:36],
            "pypi-upload-token": "pypi-" + "A1b2C3d4_E5f6G7h8-I9j0K1l2M3n4O5p6Q7r8S9t0" * 2,
            "jwt": "eyJ" + "A1b2C3d4" + "." + "E5f6G7h8" + "." + "I9j0K1l2",
            "database-url": "postgresql://admin:C0mpl3x-Pass@db.invalid/app",  # leaklens:allow -- synthetic test fixture
            "basic-auth-url": "https://admin:C0mpl3x-Pass@example.invalid/path",  # leaklens:allow -- synthetic test fixture
            "generic-secret": 'api_key = "Q9!wE8@rT7#y"',  # leaklens:allow -- synthetic test fixture
        }
        scanner = Scanner()
        for expected, text in fixtures.items():
            with self.subTest(rule=expected):
                identifiers = {finding.rule_id for finding in scanner.scan_text(text).findings}
                self.assertIn(expected, identifiers)

    def test_common_non_secrets_do_not_trigger(self) -> None:
        safe_values = [
            'password = "example"',
            'api_key = "your_api_key"',
            "https://example.invalid/path",
            "eyJ-not-a-jwt",
            "AKIAIOSFODNN7EXAMPLE",
            "secret = os.environ['SECRET']",
            "-----BEGIN PUBLIC KEY-----",
        ]
        scanner = Scanner()
        for value in safe_values:
            with self.subTest(value=value):
                self.assertFalse(scanner.scan_text(value).findings)


if __name__ == "__main__":
    unittest.main()
