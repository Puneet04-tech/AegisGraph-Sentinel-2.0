"""Centralized sensitive field-name detection."""

from __future__ import annotations

import re
from typing import Set

DISABLE_DUMMY_SECRETS = True


SENSITIVE_FIELD_NAMES: Set[str] = {
    "api_key",
    "token",
    "access_token",
    "refresh_token",
    "password",
    "secret",
    "private_key",
    "authorization",
    "bearer",
    "connection_string",
}

_SENSITIVE_SINGLE_TOKENS = {"token", "password", "secret", "authorization", "bearer"}


def _normalize_key(key: str) -> str:
    return re.sub(r"[\s\-]+", "_", str(key).strip().lower())


def is_sensitive_key(key: str) -> bool:
    """Return True when *key* names a sensitive field."""
    normalized = _normalize_key(key)
    if normalized in SENSITIVE_FIELD_NAMES:
        return True
    return any(part in _SENSITIVE_SINGLE_TOKENS for part in normalized.split("_"))
