"""
Audit dispatch with observable failures.

Four security modules emitted their audit events inside
``try: ... except Exception: pass``. The intent was right -- an audit-logging
failure must never break the authorization check or threat detection it
accompanies -- but the handler swallowed the *evidence* along with the
exception. Nothing distinguished "no security events occurred" from "every
security event failed to record".

This module keeps the non-propagating guarantee and makes the loss visible.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

# Dropped events per source, so an operator can see that a trail is incomplete.
_dropped: Dict[str, int] = {}
_lock = threading.Lock()


def dispatch_audit(
    audit_logger: Optional[Callable[..., Any]],
    audit_source: str,
    event_type: str,
    **fields: Any,
) -> bool:
    """Emit one audit event, reporting rather than hiding any failure.

    Args:
        audit_logger: The audit callable, or None when auditing is disabled.
        audit_source: Owning module, used to attribute dropped events. Named
            distinctly from any `source` field a caller may pass through.
        event_type: The event being recorded.
        **fields: Passed through to the audit callable unchanged.

    Returns:
        True if the event was accepted, False if it was dropped. Never raises:
        a failure here must not break the security operation being audited.
    """
    if audit_logger is None:
        return False

    try:
        audit_logger(event_type=event_type, **fields)
        return True
    except Exception as exc:
        record_drop(audit_source)
        # Reported through this module's own logger, never back through the
        # audit logger that just failed. The payload is deliberately omitted:
        # it may carry sensitive metadata, and the event type plus the
        # exception are enough to diagnose the sink.
        logger.error(
            "Audit event dropped: source=%s event_type=%s error=%s: %s",
            audit_source,
            event_type,
            type(exc).__name__,
            exc,
        )
        return False


def record_drop(source: str) -> None:
    """Count a dropped security event from a non-audit path."""
    with _lock:
        _dropped[source] = _dropped.get(source, 0) + 1


def dropped_events(source: Optional[str] = None) -> int:
    """Number of audit events discarded, overall or for one source."""
    with _lock:
        if source is None:
            return sum(_dropped.values())
        return _dropped.get(source, 0)


def dropped_by_source() -> Dict[str, int]:
    """Snapshot of dropped-event counts per source."""
    with _lock:
        return dict(_dropped)


def reset_dropped() -> None:
    """Clear the counters (used by tests)."""
    with _lock:
        _dropped.clear()
