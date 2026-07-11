from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from leaklens.engine import Scanner
from leaklens.filesystem import FileScanner, decode_text


class FileScannerTests(unittest.TestCase):
    def test_scans_text_but_skips_binary_excluded_and_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text('password = "Q9!wE8@rT7#y"', encoding="utf-8")
            (root / "ignored.log").write_text('password = "A1!bB2@cC3#d"', encoding="utf-8")
            (root / "image.bin").write_bytes(b"\x00secret\xff")
            (root / "huge.txt").write_text("x" * 100, encoding="utf-8")
            result = FileScanner(Scanner(), excludes=("*.log",), max_file_size=50).scan_paths([root])
        self.assertEqual(len(result.findings), 1)
        self.assertTrue(result.findings[0].location.path.endswith("app.py"))
        self.assertEqual(result.stats.binary_skipped, 1)
        self.assertEqual(result.stats.oversized_skipped, 1)

    def test_decodes_utf16_and_rejects_null_binary(self) -> None:
        self.assertEqual(decode_text("hello".encode("utf-16")), "hello")
        self.assertIsNone(decode_text(b"abc\x00def"))


if __name__ == "__main__":
    unittest.main()

