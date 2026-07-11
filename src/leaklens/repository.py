"""Git worktree, staged diff, and history scanning."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .engine import Scanner
from .filesystem import FileScanner, decode_text
from .models import Finding, Location, ScanResult


class GitError(RuntimeError):
    """Raised when Git cannot provide a trustworthy view."""


@dataclass(slots=True)
class RepositoryScanner:
    root: Path
    scanner: Scanner
    file_scanner: FileScanner
    timeout: float = 30.0

    def __post_init__(self) -> None:
        self.root = self.root.resolve()
        top = self._git("rev-parse", "--show-toplevel").decode().strip()
        if Path(top).resolve() != self.root:
            raise GitError(f"{self.root} is not the Git repository root ({top})")

    def scan_worktree(self) -> ScanResult:
        raw = self._git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
        paths = [
            self.root / item.decode("utf-8", errors="surrogateescape")
            for item in raw.split(b"\0")
            if item
        ]
        return self.file_scanner.scan_paths(paths)

    def scan_staged(self) -> ScanResult:
        raw_patch = self._git(
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-color",
            "--unified=0",
            "--diff-filter=ACMR",
            "--",
        )
        patch_limit = max(16 * 1024 * 1024, self.file_scanner.max_file_size * 20)
        if len(raw_patch) > patch_limit:
            raise GitError(
                f"staged diff is {len(raw_patch)} bytes, above safety limit {patch_limit}; scan files directly"
            )
        patch = raw_patch.decode("utf-8", errors="replace")
        result = ScanResult()
        current_path = "<staged>"
        new_line = 0
        for line in patch.splitlines():
            if line.startswith("+++ b/"):
                current_path = line[6:]
                continue
            if line.startswith("@@"):
                match = re.search(r"\+(\d+)(?:,(\d+))?", line)
                if match:
                    new_line = int(match.group(1))
                continue
            if line.startswith("+") and not line.startswith("+++"):
                scanned = self.scanner.scan_text(line[1:] + "\n", path=current_path)
                _shift_lines(scanned, new_line - 1)
                result.extend(scanned)
                new_line += 1
            elif line.startswith(" "):
                new_line += 1
        return result

    def scan_history(self, *, max_commits: int = 1_000, since: str | None = None) -> ScanResult:
        arguments = ["rev-list", "--all", "--reverse", f"--max-count={max_commits + 1}"]
        if since:
            arguments.append(f"--since={since}")
        commits = [item for item in self._git(*arguments).decode().splitlines() if item]
        if len(commits) > max_commits:
            raise GitError(
                f"history contains {len(commits)} commits, above limit {max_commits}; raise history_max_commits explicitly"
            )
        result = ScanResult()
        seen: set[tuple[str, str]] = set()
        for commit in commits:
            names = self._git(
                "diff-tree",
                "--root",
                "--no-commit-id",
                "--name-only",
                "-z",
                "-r",
                "--diff-filter=AM",
                commit,
            )
            for raw_name in names.split(b"\0"):
                if not raw_name:
                    continue
                path = raw_name.decode("utf-8", errors="surrogateescape")
                try:
                    size_text = self._git("cat-file", "-s", f"{commit}:{path}").decode().strip()
                    size = int(size_text)
                    if size > self.file_scanner.max_file_size:
                        result.stats.files_skipped += 1
                        result.stats.oversized_skipped += 1
                        continue
                    raw = self._git("show", f"{commit}:{path}")
                except (GitError, ValueError) as exc:
                    result.errors.append(str(exc))
                    continue
                text = decode_text(raw)
                if text is None:
                    result.stats.files_skipped += 1
                    result.stats.binary_skipped += 1
                    continue
                scanned = self.scanner.scan_text(text, path=path, commit=commit)
                unique: list[Finding] = []
                for finding in scanned.findings:
                    key = (finding.fingerprint, path)
                    if key not in seen:
                        seen.add(key)
                        unique.append(finding)
                    else:
                        scanned.stats.findings_suppressed += 1
                scanned.findings = unique
                result.extend(scanned)
        return result

    def _git(self, *arguments: str) -> bytes:
        try:
            process = subprocess.run(
                ["git", "-c", "core.quotepath=false", *arguments],
                cwd=self.root,
                check=False,
                capture_output=True,
                timeout=self.timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitError(f"git {' '.join(arguments)} failed: {exc}") from exc
        if process.returncode:
            message = process.stderr.decode("utf-8", errors="replace").strip()
            raise GitError(
                f"git {' '.join(arguments)} failed: {message or f'exit {process.returncode}'}"
            )
        return process.stdout


def _shift_lines(result: ScanResult, offset: int) -> None:
    result.findings = [
        Finding(
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity,
            confidence=finding.confidence,
            location=Location(
                path=finding.location.path,
                line=finding.location.line + offset,
                column=finding.location.column,
                end_line=finding.location.end_line + offset,
                end_column=finding.location.end_column,
                commit=finding.location.commit,
            ),
            fingerprint=finding.fingerprint,
            redacted=finding.redacted,
            secret_length=finding.secret_length,
            entropy=finding.entropy,
            message=finding.message,
            tags=finding.tags,
        )
        for finding in result.findings
    ]
