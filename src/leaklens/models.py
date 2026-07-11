"""Stable, redaction-safe domain models."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Finding priority; numeric ordering is intentional."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError as exc:
            choices = ", ".join(member.name.lower() for member in cls)
            raise ValueError(f"unknown severity {value!r}; choose from {choices}") from exc

    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class Location:
    path: str
    line: int
    column: int
    end_line: int
    end_column: int
    commit: str | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    """A secret candidate. The raw value is never serialized or represented."""

    rule_id: str
    title: str
    severity: Severity
    confidence: str
    location: Location
    fingerprint: str
    redacted: str
    secret_length: int
    entropy: float
    message: str
    tags: tuple[str, ...] = ()
    _secret: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["severity"] = self.severity.label()
        result.pop("_secret", None)
        return result


@dataclass(slots=True)
class ScanStats:
    files_scanned: int = 0
    bytes_scanned: int = 0
    files_skipped: int = 0
    binary_skipped: int = 0
    oversized_skipped: int = 0
    findings_suppressed: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    errors: list[str] = field(default_factory=list)

    @property
    def highest_severity(self) -> Severity | None:
        return max((finding.severity for finding in self.findings), default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "findings": [finding.to_dict() for finding in self.findings],
            "stats": self.stats.to_dict(),
            "errors": self.errors,
        }


def fingerprint(rule_id: str, secret: str) -> str:
    """Return a stable, domain-separated digest without retaining the secret."""

    digest = hashlib.blake2s(digest_size=20, person=b"LeakLn01")
    digest.update(rule_id.encode("utf-8"))
    digest.update(b"\0")
    digest.update(secret.encode("utf-8", errors="surrogatepass"))
    return digest.hexdigest()


def redact(secret: str) -> str:
    """Show enough shape to recognize a credential without exposing it."""

    if len(secret) <= 8:
        return "•" * len(secret)
    visible = 3 if len(secret) < 20 else 4
    return f"{secret[:visible]}…{secret[-visible:]}"
