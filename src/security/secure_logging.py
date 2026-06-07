"""Reusable helpers for safe structured logging payloads."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .sanitizers import sanitize_metadata, sanitize_payload


def safe_log_metadata(metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return metadata safe to pass to existing loggers."""
    return sanitize_metadata(metadata)


def safe_log_event(
    event_type: str,
    payload: Optional[Dict[str, Any]] = None,
    *,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a sanitized event envelope for diagnostics or logging."""
    return {
        "event_type": event_type,
        "payload": sanitize_payload(payload),
        "metadata": sanitize_metadata(metadata),
    }
