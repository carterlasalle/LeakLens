"""Entropy and candidate-quality helpers."""

from __future__ import annotations

import math
from collections import Counter


def shannon(value: str) -> float:
    """Calculate Shannon entropy in bits per character."""

    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


_PLACEHOLDERS = {
    "changeme",
    "example",
    "fake",
    "placeholder",
    "replace_me",
    "replace-with-real-value",
    "secret",
    "test",
    "todo",
    "your_api_key",
    "your_token_here",
}


def looks_placeholder(value: str) -> bool:
    normalized = value.strip("'\" <>[]{}()").casefold()
    if normalized in _PLACEHOLDERS:
        return True
    return any(
        marker in normalized for marker in ("example", "placeholder", "your_", "xxxx", "dummy")
    )


def character_classes(value: str) -> int:
    return sum(
        (
            any(char.islower() for char in value),
            any(char.isupper() for char in value),
            any(char.isdigit() for char in value),
            any(not char.isalnum() for char in value),
        )
    )
