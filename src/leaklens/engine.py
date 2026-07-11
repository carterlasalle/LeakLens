"""Pure scanning engine with no filesystem or Git assumptions."""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field

from .entropy import shannon
from .models import Finding, Location, ScanResult, Severity, fingerprint, redact
from .rules import Rule, builtin_rules


@dataclass(slots=True)
class Scanner:
    """Scan text using ordered rules and deterministic suppression semantics."""

    rules: tuple[Rule, ...] = field(default_factory=builtin_rules)
    minimum_severity: Severity = Severity.LOW
    allowed_fingerprints: frozenset[str] = frozenset()
    max_findings: int = 10_000

    def scan_text(
        self,
        text: str,
        *,
        path: str = "<memory>",
        commit: str | None = None,
    ) -> ScanResult:
        result = ScanResult()
        result.stats.files_scanned = 1
        result.stats.bytes_scanned = len(text.encode("utf-8", errors="surrogatepass"))
        line_starts = [0]
        line_starts.extend(index + 1 for index, char in enumerate(text) if char == "\n")
        occupied: list[tuple[int, int]] = []
        limit_reached = False
        folded = text.casefold()

        for rule in self.rules:
            if rule.severity < self.minimum_severity:
                continue
            if rule.keywords and not any(keyword in folded for keyword in rule.keywords):
                continue
            for match in rule.pattern.finditer(text):
                start, end = match.span(rule.secret_group)
                if any(
                    start < previous_end and end > previous_start
                    for previous_start, previous_end in occupied
                ):
                    continue
                secret = match.group(rule.secret_group)
                if not rule.accepts(secret):
                    result.stats.findings_suppressed += 1
                    continue
                line_index = bisect.bisect_right(line_starts, start) - 1
                line_number = line_index + 1
                line_start = line_starts[line_index]
                line_end = text.find("\n", line_start)
                if line_end == -1:
                    line_end = len(text)
                line_text = text[line_start:line_end]
                previous_line = ""
                if line_index > 0:
                    previous_start = line_starts[line_index - 1]
                    previous_line = text[previous_start : line_start - 1]
                next_line = ""
                if line_end < len(text):
                    next_end = text.find("\n", line_end + 1)
                    if next_end == -1:
                        next_end = len(text)
                    next_line = text[line_end + 1 : next_end]
                if any(
                    "leaklens:allow" in candidate.casefold()
                    for candidate in (previous_line, line_text, next_line)
                ):
                    result.stats.findings_suppressed += 1
                    continue
                secret_fingerprint = fingerprint(rule.id, secret)
                if secret_fingerprint in self.allowed_fingerprints:
                    result.stats.findings_suppressed += 1
                    continue
                end_line_index = bisect.bisect_right(line_starts, max(start, end - 1)) - 1
                finding = Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    location=Location(
                        path=path,
                        line=line_number,
                        column=start - line_start + 1,
                        end_line=end_line_index + 1,
                        end_column=end - line_starts[end_line_index] + 1,
                        commit=commit,
                    ),
                    fingerprint=secret_fingerprint,
                    redacted=redact(secret),
                    secret_length=len(secret),
                    entropy=round(shannon(secret), 3),
                    message=rule.message,
                    tags=rule.tags,
                )
                result.findings.append(finding)
                occupied.append((start, end))
                if len(result.findings) >= self.max_findings:
                    result.errors.append(
                        f"finding limit {self.max_findings} reached in {path}; narrow the scan or raise the limit in code"
                    )
                    limit_reached = True
                    break
            if limit_reached:
                break

        result.findings.sort(
            key=lambda item: (
                -int(item.severity),
                item.location.path,
                item.location.line,
                item.location.column,
                item.rule_id,
            )
        )
        return result
