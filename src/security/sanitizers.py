"""Small sanitizers for runtime metadata and payload dictionaries."""

from __future__ import annotations

from typing import Any

from .redaction import redact_value


def sanitize_metadata(metadata: Any = None) -> Any:
    """Sanitize structured log metadata."""
    return redact_value(metadata or {})


def sanitize_payload(payload: Any = None) -> Any:
    """Sanitize runtime event or response payloads."""
    return redact_value(payload or {})


def sanitize_exception_context(context: Any = None) -> Any:
    """Sanitize exception context before logging or returning it."""
    return redact_value(context or {})
