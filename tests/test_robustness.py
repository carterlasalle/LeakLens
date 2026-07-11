"""Deterministic fuzz-style tests for parser and regex resilience."""

from __future__ import annotations

import random
import string
import unittest

from leaklens.engine import Scanner
from leaklens.filesystem import decode_text


class RobustnessTests(unittest.TestCase):
    def test_arbitrary_unicode_never_escapes_scanner_exceptions(self) -> None:
        randomizer = random.Random(0x4C45414B4C454E53)
        alphabet = string.printable + "éø中🔐\ud800"
        scanner = Scanner(max_findings=100)
        for index in range(2_000):
            text = "".join(randomizer.choice(alphabet) for _ in range(randomizer.randrange(0, 1024)))
            result = scanner.scan_text(text, path=f"fuzz-{index}")
            self.assertLessEqual(len(result.findings), 100)

    def test_arbitrary_bytes_are_safely_decoded_or_classified_binary(self) -> None:
        randomizer = random.Random(0x53414645)
        for _ in range(2_000):
            raw = randomizer.randbytes(randomizer.randrange(0, 2048))
            decoded = decode_text(raw)
            self.assertTrue(decoded is None or isinstance(decoded, str))

    def test_long_adversarial_line_completes(self) -> None:
        value = "api_key=" + "'" + "a" * 1_000_000 + "'"
        result = Scanner().scan_text(value)
        self.assertFalse(result.findings)


if __name__ == "__main__":
    unittest.main()
