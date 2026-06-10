"""Rolling in-memory audit buffer."""

from __future__ import annotations

import threading
from collections import deque
from typing import Any, Deque, Dict, List

from .audit_event import AuditEvent
from .integrity import compute_hash


AuditRecord = Dict[str, Any]


class AuditStore:
    def __init__(self, max_size: int = 1000) -> None:
        self._records: Deque[AuditRecord] = deque(maxlen=max_size)
        self._lock = threading.Lock()

    def append(self, event: AuditEvent) -> AuditRecord:
        with self._lock:
            previous_hash = self._records[-1]["current_hash"] if self._records else ""
            record = {
                "event": event,
                "previous_hash": previous_hash,
                "current_hash": compute_hash(previous_hash, event),
            }
            self._records.append(record)
            return record

    def get_events(self) -> List[AuditRecord]:
        with self._lock:
            return list(self._records)

    def get_by_correlation_id(self, correlation_id: str) -> List[AuditRecord]:
        with self._lock:
            return [
                record for record in self._records
                if record["event"].correlation_id == correlation_id
            ]

    def get_by_event_type(self, event_type: str) -> List[AuditRecord]:
        with self._lock:
            return [
                record for record in self._records
                if record["event"].event_type == event_type
            ]


default_audit_store = AuditStore()
