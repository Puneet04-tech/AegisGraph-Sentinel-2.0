"""Recursive value redaction helpers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .secrets import is_sensitive_key


REDACTED_VALUE = "[REDACTED]"


def redact_value(value: Any) -> Any:
    """Recursively redact sensitive fields while preserving basic structure."""
    if isinstance(value, Mapping):
        return redact_dict(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    return value


def redact_dict(data: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a redacted copy of a mapping."""
    if data is None:
        return {}

    redacted: dict[str, Any] = {}
    for key, value in data.items():
        if is_sensitive_key(str(key)):
            redacted[key] = REDACTED_VALUE
        else:
            redacted[key] = redact_value(value)
    return redacted
