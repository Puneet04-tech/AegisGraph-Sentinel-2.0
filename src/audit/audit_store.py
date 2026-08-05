"""Rolling in-memory audit buffer."""

from __future__ import annotations

import threading
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional

from .audit_event import AuditEvent
from .integrity import compute_hash, verify_chain


AuditRecord = Dict[str, Any]


class AuditStore:
    def __init__(
        self,
        max_size: int = 1000,
        archive_callback: Optional[Callable[[AuditRecord], None]] = None,
    ) -> None:
        self._records: Deque[AuditRecord] = deque(maxlen=max_size)
        self._lock = threading.Lock()
        self._last_evicted_hash: Optional[str] = None
        self._archive_callback = archive_callback

    def set_archive_callback(
        self, callback: Optional[Callable[[AuditRecord], None]]
    ) -> None:
        with self._lock:
            self._archive_callback = callback

    def get_initial_hash_anchor(self) -> Optional[str]:
        with self._lock:
            return self._last_evicted_hash

    def append(self, event: AuditEvent) -> AuditRecord:
        with self._lock:
            if self._records and len(self._records) == self._records.maxlen:
                evicted = self._records[0]
                self._last_evicted_hash = evicted["current_hash"]
                if self._archive_callback is not None:
                    try:
                        self._archive_callback(evicted)
                    except Exception:
                        pass
            previous_hash = self._records[-1]["current_hash"] if self._records else ""
            record = {
                "event": event,
                "previous_hash": previous_hash,
                "current_hash": compute_hash(previous_hash, event),
            }
            self._records.append(record)
            return record

    def verify(self) -> bool:
        with self._lock:
            return verify_chain(self._records, initial_hash_anchor=self._last_evicted_hash)

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
