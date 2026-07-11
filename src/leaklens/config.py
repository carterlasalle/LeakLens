"""Project configuration loaded with Python's standard TOML parser."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Severity
from .rules import Rule, validate_custom_rule


class ConfigError(ValueError):
    """Raised when `.leaklens.toml` is invalid or unsafe."""


DEFAULT_EXCLUDES = (
    ".git/**",
    ".hg/**",
    ".svn/**",
    ".venv/**",
    "venv/**",
    "node_modules/**",
    "vendor/**",
    "dist/**",
    "build/**",
    "coverage/**",
    "*.min.js",
    "*.map",
    "*.lock",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.pdf",
    "*.zip",
    "*.gz",
)


@dataclass(frozen=True, slots=True)
class Config:
    minimum_severity: Severity = Severity.LOW
    max_file_size: int = 5 * 1024 * 1024
    excludes: tuple[str, ...] = DEFAULT_EXCLUDES
    allowed_fingerprints: frozenset[str] = frozenset()
    custom_rules: tuple[Rule, ...] = ()
    follow_symlinks: bool = False
    scan_hidden: bool = False
    history_max_commits: int = 1_000
    baseline_path: str = ".leaklens-baseline.json"


def find_config(start: str | Path = ".") -> Path | None:
    current = Path(start).resolve()
    if current.is_file():
        current = current.parent
    while True:
        candidate = current / ".leaklens.toml"
        if candidate.is_file():
            return candidate
        if current.parent == current:
            return None
        current = current.parent


def load_config(path: str | Path | None = None) -> Config:
    if path is None:
        discovered = find_config()
        if discovered is None:
            return Config()
        path = discovered
    config_path = Path(path)
    try:
        with config_path.open("rb") as stream:
            data = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot load {config_path}: {exc}") from exc
    try:
        scan = _table(data, "scan")
        baseline = _table(data, "baseline")
        minimum = Severity.parse(str(scan.get("minimum_severity", "low")))
        max_file_size = int(scan.get("max_file_size", 5 * 1024 * 1024))
        history_max = int(scan.get("history_max_commits", 1_000))
        if max_file_size < 1 or max_file_size > 1024 * 1024 * 1024:
            raise ConfigError("scan.max_file_size must be between 1 byte and 1 GiB")
        if history_max < 1 or history_max > 1_000_000:
            raise ConfigError("scan.history_max_commits must be between 1 and 1,000,000")
        excludes = DEFAULT_EXCLUDES + tuple(_strings(scan.get("exclude", []), "scan.exclude"))
        allowed = frozenset(_strings(data.get("allow_fingerprints", []), "allow_fingerprints"))
        rules = tuple(_parse_rule(item) for item in _tables(data.get("rules", []), "rules"))
        return Config(
            minimum_severity=minimum,
            max_file_size=max_file_size,
            excludes=excludes,
            allowed_fingerprints=allowed,
            custom_rules=rules,
            follow_symlinks=bool(scan.get("follow_symlinks", False)),
            scan_hidden=bool(scan.get("scan_hidden", False)),
            history_max_commits=history_max,
            baseline_path=str(baseline.get("path", ".leaklens-baseline.json")),
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(f"invalid {config_path}: {exc}") from exc


def _parse_rule(item: dict[str, Any]) -> Rule:
    try:
        flags = re.MULTILINE | (re.IGNORECASE if item.get("ignore_case", False) else 0)
        rule = Rule(
            id=str(item["id"]),
            title=str(item.get("title", item["id"])),
            pattern=re.compile(str(item["pattern"]), flags),
            severity=Severity.parse(str(item.get("severity", "high"))),
            confidence=str(item.get("confidence", "medium")),
            secret_group=str(item.get("secret_group", "secret")),
            minimum_entropy=float(item.get("minimum_entropy", 0.0)),
            tags=tuple(_strings(item.get("tags", ["custom"]), "rules.tags")),
            message=str(item.get("message", "Custom rule matched a potential credential")),
            reject_placeholders=bool(item.get("reject_placeholders", True)),
            keywords=tuple(_strings(item.get("keywords", []), "rules.keywords")),
        )
        validate_custom_rule(rule)
        return rule
    except (KeyError, re.error, TypeError, ValueError) as exc:
        raise ConfigError(f"invalid custom rule: {exc}") from exc


def _table(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{key} must be a TOML table")
    return value


def _tables(value: object, name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ConfigError(f"{name} must be an array of TOML tables")
    return value


def _strings(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"{name} must be an array of strings")
    return value
