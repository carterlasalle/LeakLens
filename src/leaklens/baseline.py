"""Versioned baselines that store fingerprints, never secret values."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import Finding


class BaselineError(ValueError):
    """Raised for malformed or unsupported baseline files."""


@dataclass(frozen=True, slots=True)
class Baseline:
    fingerprints: frozenset[str]
    generated_at: str

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> Baseline:
        return cls(
            fingerprints=frozenset(finding.fingerprint for finding in findings),
            generated_at=datetime.now(tz=UTC).replace(microsecond=0).isoformat(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "generated_at": self.generated_at,
            "fingerprints": sorted(self.fingerprints),
        }


def load_baseline(path: str | Path) -> Baseline:
    baseline_path = Path(path)
    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"cannot load {baseline_path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise BaselineError("unsupported baseline schema; expected version 1")
    values = data.get("fingerprints")
    if not isinstance(values, list) or any(
        not isinstance(value, str) or not _is_fingerprint(value) for value in values
    ):
        raise BaselineError("baseline fingerprints must be 40-character hexadecimal strings")
    generated_at = data.get("generated_at")
    if not isinstance(generated_at, str):
        raise BaselineError("baseline generated_at must be a string")
    return Baseline(frozenset(values), generated_at)


def save_baseline(path: str | Path, baseline: Baseline) -> None:
    destination = Path(path)
    destination.write_text(json.dumps(baseline.to_dict(), indent=2) + "\n", encoding="utf-8")


def _is_fingerprint(value: str) -> bool:
    return len(value) == 40 and all(char in "0123456789abcdef" for char in value)

