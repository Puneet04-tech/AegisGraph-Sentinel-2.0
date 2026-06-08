"""Lightweight diagnostic scanner for sensitive keys."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Dict, List

from .secrets import is_sensitive_key


def scan_for_secrets(data: Any) -> Dict[str, Any]:
    """Return sensitive keys detected in nested dict/list data."""
    detected: List[str] = []

    def _scan(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                key_text = str(key)
                if is_sensitive_key(key_text):
                    detected.append(key_text)
                _scan(item)
        elif isinstance(value, list):
            for item in value:
                _scan(item)
        elif isinstance(value, tuple):
            for item in value:
                _scan(item)

    _scan(data)
    return {"detected_keys": detected, "count": len(detected)}
