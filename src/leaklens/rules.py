"""Built-in and custom secret detection rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Pattern

from .entropy import character_classes, looks_placeholder, shannon
from .models import Severity


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    pattern: Pattern[str]
    severity: Severity
    confidence: str
    secret_group: str = "secret"
    minimum_entropy: float = 0.0
    tags: tuple[str, ...] = ()
    message: str = "Potential credential committed to source"
    reject_placeholders: bool = False

    def accepts(self, secret: str) -> bool:
        if self.reject_placeholders and looks_placeholder(secret):
            return False
        return shannon(secret) >= self.minimum_entropy


def _rule(
    id: str,
    title: str,
    expression: str,
    severity: Severity,
    *,
    confidence: str = "high",
    entropy: float = 0.0,
    tags: tuple[str, ...] = (),
    message: str = "Potential credential committed to source",
    reject_placeholders: bool = False,
) -> Rule:
    return Rule(
        id=id,
        title=title,
        pattern=re.compile(expression, re.IGNORECASE | re.MULTILINE),
        severity=severity,
        confidence=confidence,
        minimum_entropy=entropy,
        tags=tags,
        message=message,
        reject_placeholders=reject_placeholders,
    )


@lru_cache(maxsize=1)
def builtin_rules() -> tuple[Rule, ...]:
    """Return the versioned built-in detector catalog."""

    critical = Severity.CRITICAL
    high = Severity.HIGH
    return (
        _rule("private-key", "Private key", r"(?P<secret>-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)", critical, tags=("key", "asymmetric"), message="Private key material begins here"),
        _rule("github-pat", "GitHub personal access token", r"(?<![A-Za-z0-9_])(?P<secret>github_pat_[A-Za-z0-9_]{20,255}|gh[pousr]_[A-Za-z0-9]{36,255})(?![A-Za-z0-9_])", critical, tags=("github", "token")),
        _rule("gitlab-pat", "GitLab personal access token", r"(?<![A-Za-z0-9_-])(?P<secret>glpat-[A-Za-z0-9_-]{20,255})(?![A-Za-z0-9_-])", critical, tags=("gitlab", "token")),
        _rule("aws-access-key", "AWS access key ID", r"(?<![A-Z0-9])(?P<secret>(?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])", high, tags=("aws", "cloud", "identifier")),
        _rule("google-api-key", "Google API key", r"(?<![A-Za-z0-9_-])(?P<secret>AIza[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])", high, tags=("google", "cloud", "token")),
        _rule("slack-token", "Slack token", r"(?<![A-Za-z0-9-])(?P<secret>xox[baprs]-[A-Za-z0-9-]{10,250})(?![A-Za-z0-9-])", critical, tags=("slack", "token")),
        _rule("stripe-live-key", "Stripe live secret key", r"(?<![A-Za-z0-9_])(?P<secret>(?:sk|rk)_live_[A-Za-z0-9]{20,255})(?![A-Za-z0-9_])", critical, tags=("stripe", "payment", "token")),
        _rule("openai-api-key", "OpenAI API key", r"(?<![A-Za-z0-9_-])(?P<secret>sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,255})(?![A-Za-z0-9_-])", critical, entropy=3.0, tags=("openai", "ai", "token")),
        _rule("anthropic-api-key", "Anthropic API key", r"(?<![A-Za-z0-9_-])(?P<secret>sk-ant-[A-Za-z0-9_-]{20,255})(?![A-Za-z0-9_-])", critical, entropy=3.0, tags=("anthropic", "ai", "token")),
        _rule("sendgrid-api-key", "SendGrid API key", r"(?<![A-Za-z0-9_.-])(?P<secret>SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{32,64})(?![A-Za-z0-9_.-])", critical, tags=("sendgrid", "email", "token")),
        _rule("npm-access-token", "npm access token", r"(?<![A-Za-z0-9_])(?P<secret>npm_[A-Za-z0-9]{36})(?![A-Za-z0-9_])", critical, tags=("npm", "supply-chain", "token")),
        _rule("pypi-upload-token", "PyPI upload token", r"(?<![A-Za-z0-9_-])(?P<secret>pypi-[A-Za-z0-9_-]{50,255})(?![A-Za-z0-9_-])", critical, tags=("pypi", "supply-chain", "token")),
        _rule("jwt", "JSON Web Token", r"(?<![A-Za-z0-9_-])(?P<secret>eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,})(?![A-Za-z0-9_-])", high, entropy=3.0, tags=("jwt", "token"), message="JWT-like bearer credential"),
        _rule("database-url", "Database connection URL", r"(?P<secret>(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^\s:'\"]+:[^\s@'\"]+@[^\s'\"]+)", critical, tags=("database", "password"), message="Connection URL contains inline credentials"),
        _rule("basic-auth-url", "URL with embedded credentials", r"(?P<secret>https?://[^\s:/@'\"]+:[^\s/@'\"]+@[^\s'\"]+)", high, tags=("url", "password"), message="URL contains inline credentials"),
        _rule("generic-secret", "Generic assigned secret", r"(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|secret)\s*[=:]\s*['\"](?P<secret>[^'\"\r\n]{8,512})['\"]", high, confidence="medium", entropy=3.0, tags=("generic", "assignment"), reject_placeholders=True),
    )


def validate_custom_rule(rule: Rule) -> None:
    if not re.fullmatch(r"[a-z][a-z0-9-]{2,63}", rule.id):
        raise ValueError(f"invalid rule id {rule.id!r}")
    if rule.secret_group not in rule.pattern.groupindex:
        raise ValueError(f"rule {rule.id!r} pattern must define (?P<{rule.secret_group}>...)")
    if rule.minimum_entropy < 0.0:
        raise ValueError("minimum entropy cannot be negative")


def generic_candidate_is_strong(value: str) -> bool:
    return len(value) >= 12 and shannon(value) >= 3.0 and character_classes(value) >= 2

