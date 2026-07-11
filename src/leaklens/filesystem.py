"""Safe filesystem traversal and text decoding."""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .engine import Scanner
from .models import ScanResult


@dataclass(slots=True)
class FileScanner:
    scanner: Scanner
    excludes: tuple[str, ...] = ()
    max_file_size: int = 5 * 1024 * 1024
    follow_symlinks: bool = False
    scan_hidden: bool = False

    def scan_paths(self, paths: Sequence[str | Path]) -> ScanResult:
        result = ScanResult()
        seen: set[tuple[int, int]] = set()
        for path in self.iter_files(paths):
            try:
                stat = path.stat(follow_symlinks=self.follow_symlinks)
                identity = (stat.st_dev, stat.st_ino)
                if identity in seen:
                    result.stats.files_skipped += 1
                    continue
                seen.add(identity)
                if stat.st_size > self.max_file_size:
                    result.stats.files_skipped += 1
                    result.stats.oversized_skipped += 1
                    continue
                raw = path.read_bytes()
                text = decode_text(raw)
                if text is None:
                    result.stats.files_skipped += 1
                    result.stats.binary_skipped += 1
                    continue
                scanned = self.scanner.scan_text(text, path=path.as_posix())
                result.extend(scanned)
            except OSError as exc:
                result.errors.append(f"{path}: {exc}")
        return result

    def iter_files(self, paths: Sequence[str | Path]) -> list[Path]:
        discovered: list[Path] = []
        for raw_path in paths:
            path = Path(raw_path)
            if path.is_symlink() and not self.follow_symlinks:
                continue
            if path.is_file():
                if not self._excluded(path):
                    discovered.append(path)
                continue
            if not path.is_dir():
                continue
            for root, directories, files in os.walk(path, followlinks=self.follow_symlinks):
                root_path = Path(root)
                directories[:] = [
                    directory
                    for directory in directories
                    if (self.scan_hidden or not directory.startswith("."))
                    and not self._excluded(root_path / directory, directory=True)
                ]
                for filename in files:
                    candidate = root_path / filename
                    if candidate.is_symlink() and not self.follow_symlinks:
                        continue
                    if not self._excluded(candidate):
                        discovered.append(candidate)
        return sorted(set(discovered), key=lambda item: item.as_posix())

    def _excluded(self, path: Path, *, directory: bool = False) -> bool:
        normalized = path.as_posix().lstrip("./") + ("/" if directory else "")
        name = path.name + ("/" if directory else "")
        if not self.scan_hidden and any(
            part.startswith(".") for part in path.parts if part not in {".", ".."}
        ):
            return True
        return any(
            fnmatch.fnmatch(normalized, pattern)
            or fnmatch.fnmatch(name, pattern)
            or fnmatch.fnmatch(normalized, f"*/{pattern}")
            for pattern in self.excludes
        )


def decode_text(raw: bytes) -> str | None:
    if not raw:
        return ""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            return None
    sample = raw[:8192]
    if b"\0" in sample:
        return None
    control = sum(byte < 9 or 13 < byte < 32 for byte in sample)
    if control / len(sample) > 0.15:
        return None
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            return raw.decode("utf-8", errors="replace")
        except UnicodeError:
            return None
