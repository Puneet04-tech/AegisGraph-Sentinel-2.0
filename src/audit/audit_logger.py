"""Small in-memory audit logger."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .audit_event import AuditEvent
from .audit_store import AuditRecord, AuditStore, default_audit_store
from .correlation import get_correlation_id


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class AuditLogger:
    def __init__(self, store: Optional[AuditStore] = None) -> None:
        self.store = store or default_audit_store

    def log_audit_event(
        self,
        event_type: str,
        severity: str = "info",
        source: str = "runtime",
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=_utcnow(),
            event_type=event_type,
            severity=severity,
            source=source,
            correlation_id=get_correlation_id(correlation_id),
            metadata=metadata or {},
        )
        return self.store.append(event)


default_audit_logger = AuditLogger()


def log_audit_event(
    event_type: str,
    severity: str = "info",
    source: str = "runtime",
    correlation_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditRecord:
    return default_audit_logger.log_audit_event(
        event_type=event_type,
        severity=severity,
        source=source,
        correlation_id=correlation_id,
        metadata=metadata,
    )
