"""Human-readable, machine-readable, and code-scanning output."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from typing import Any

from .models import ScanResult, Severity
from .rules import Rule

_COLORS = {
    Severity.LOW: "\x1b[36m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.HIGH: "\x1b[31m",
    Severity.CRITICAL: "\x1b[1;31m",
}
_RESET = "\x1b[0m"


def render(
    result: ScanResult, format_name: str, rules: tuple[Rule, ...], *, color: bool = False
) -> str:
    if format_name == "json":
        return json.dumps(result.to_dict(), indent=2, sort_keys=True)
    if format_name == "jsonl":
        return "\n".join(
            json.dumps(finding.to_dict(), sort_keys=True) for finding in result.findings
        )
    if format_name == "csv":
        return render_csv(result)
    if format_name == "sarif":
        return json.dumps(render_sarif(result, rules), indent=2, sort_keys=True)
    return render_table(result, color=color)


def render_table(result: ScanResult, *, color: bool = False) -> str:
    if not result.findings:
        detail = f"Scanned {result.stats.files_scanned} files / {result.stats.bytes_scanned} bytes"
        return f"✓ No secrets found\n{detail}"
    rows: list[list[str]] = []
    for finding in result.findings:
        location = f"{finding.location.path}:{finding.location.line}:{finding.location.column}"
        if finding.location.commit:
            location = f"{finding.location.commit[:8]}:{location}"
        severity = finding.severity.label().upper()
        if color:
            severity = f"{_COLORS[finding.severity]}{severity}{_RESET}"
        rows.append([severity, finding.rule_id, location, finding.redacted, finding.message])
    output = _table(["SEVERITY", "RULE", "LOCATION", "VALUE", "DETAIL"], rows)
    counts = Counter(finding.severity.label() for finding in result.findings)
    summary = ", ".join(
        f"{counts[name]} {name}" for name in ("critical", "high", "medium", "low") if counts[name]
    )
    footer = f"Found {len(result.findings)} potential secret(s): {summary}"
    suppressed = result.stats.findings_suppressed
    if suppressed:
        footer += f" · {suppressed} suppressed"
    return f"{output}\n\n{footer}"


def render_csv(result: ScanResult) -> str:
    output = io.StringIO()
    fields = [
        "rule_id",
        "title",
        "severity",
        "confidence",
        "path",
        "line",
        "column",
        "commit",
        "fingerprint",
        "redacted",
        "secret_length",
        "entropy",
        "message",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for finding in result.findings:
        writer.writerow(
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity.label(),
                "confidence": finding.confidence,
                "path": finding.location.path,
                "line": finding.location.line,
                "column": finding.location.column,
                "commit": finding.location.commit or "",
                "fingerprint": finding.fingerprint,
                "redacted": finding.redacted,
                "secret_length": finding.secret_length,
                "entropy": finding.entropy,
                "message": finding.message,
            }
        )
    return output.getvalue().rstrip()


def render_sarif(result: ScanResult, rules: tuple[Rule, ...]) -> dict[str, Any]:
    used_ids = {finding.rule_id for finding in result.findings}
    rule_map = {rule.id: rule for rule in rules}
    sarif_rules = []
    for rule_id in sorted(used_ids):
        rule = rule_map.get(rule_id)
        finding = next(item for item in result.findings if item.rule_id == rule_id)
        sarif_rules.append(
            {
                "id": rule_id,
                "name": _sarif_name(rule_id),
                "shortDescription": {"text": rule.title if rule else finding.title},
                "fullDescription": {"text": rule.message if rule else finding.message},
                "defaultConfiguration": {
                    "level": _sarif_level(rule.severity if rule else finding.severity)
                },
                "properties": {
                    "tags": list(rule.tags if rule else finding.tags),
                    "security-severity": str(
                        _security_score(rule.severity if rule else finding.severity)
                    ),
                },
            }
        )
    results = []
    for finding in result.findings:
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.location.path.replace("\\", "/")},
                "region": {
                    "startLine": finding.location.line,
                    "startColumn": finding.location.column,
                    "endLine": finding.location.end_line,
                    "endColumn": finding.location.end_column,
                },
            }
        }
        result_item: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _sarif_level(finding.severity),
            "message": {"text": f"{finding.message}. Redacted value: {finding.redacted}"},
            "locations": [location],
            "partialFingerprints": {"leakLensSecretFingerprint/v1": finding.fingerprint},
            "properties": {
                "confidence": finding.confidence,
                "entropy": finding.entropy,
                "secretLength": finding.secret_length,
            },
        }
        if finding.location.commit:
            result_item["properties"]["commit"] = finding.location.commit
        results.append(result_item)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LeakLens",
                        "informationUri": "https://github.com/carterlasalle/LeakLens",
                        "semanticVersion": "0.1.0",
                        "rules": sarif_rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "toolExecutionNotifications": [
                            {"message": {"text": error}, "level": "error"}
                            for error in result.errors
                        ],
                    }
                ],
            }
        ],
    }


def render_rules(rules: tuple[Rule, ...]) -> str:
    rows = [
        [rule.id, rule.severity.label().upper(), rule.confidence, ",".join(rule.tags), rule.title]
        for rule in sorted(rules, key=lambda item: (-int(item.severity), item.id))
    ]
    return _table(["ID", "SEVERITY", "CONFIDENCE", "TAGS", "TITLE"], rows)


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = min(72, max(widths[index], _visible_length(value)))

    def line(values: list[str]) -> str:
        rendered = []
        for index, value in enumerate(values):
            visible = _visible_length(value)
            clipped = (
                value if visible <= widths[index] else value[: max(1, widths[index] - 1)] + "…"
            )
            rendered.append(clipped + " " * max(0, widths[index] - _visible_length(clipped)))
        return "  ".join(rendered).rstrip()

    return "\n".join(
        [line(headers), line(["─" * width for width in widths]), *(line(row) for row in rows)]
    )


def _visible_length(value: str) -> int:
    clean = value
    for color in (*_COLORS.values(), _RESET):
        clean = clean.replace(color, "")
    return len(clean)


def _sarif_name(rule_id: str) -> str:
    return "".join(part.capitalize() for part in rule_id.split("-"))


def _sarif_level(severity: Severity) -> str:
    return (
        "error"
        if severity >= Severity.HIGH
        else "warning"
        if severity == Severity.MEDIUM
        else "note"
    )


def _security_score(severity: Severity) -> float:
    return {Severity.LOW: 3.0, Severity.MEDIUM: 5.5, Severity.HIGH: 8.0, Severity.CRITICAL: 9.5}[
        severity
    ]
