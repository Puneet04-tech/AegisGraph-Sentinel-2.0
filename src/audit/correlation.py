"""Small UUID-based correlation helpers."""

from __future__ import annotations

import uuid
from typing import Optional


def generate_correlation_id() -> str:
    """Generate a new UUID-based correlation ID for request tracing."""
    return str(uuid.uuid4())


def get_correlation_id(correlation_id: Optional[str] = None) -> str:
    """Return the provided correlation ID or generate a new one.

    If a correlation ID is already present in the call chain it should be passed
    in so that all related events share the same trace.  If no ID is provided a
    fresh UUID is generated and returned.

    Args:
        correlation_id: An existing correlation ID to propagate, or None to generate one.

    Returns:
        The provided *correlation_id* if truthy, otherwise a freshly generated UUID string.
    """
    return correlation_id or generate_correlation_id()
