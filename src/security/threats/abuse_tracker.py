"""In-memory counters for runtime security abuse events."""

from __future__ import annotations

import threading
from collections import Counter
from typing import Dict


class AbuseTracker:
    def __init__(self) -> None:
        self._counts: Counter[str] = Counter()
        self._lock = threading.Lock()

    def record_event(self, event_type: str) -> int:
        with self._lock:
            self._counts[event_type] += 1
            return self._counts[event_type]

    def get_count(self, event_type: str) -> int:
        with self._lock:
            return self._counts.get(event_type, 0)

    def reset(self, event_type: str) -> None:
        with self._lock:
            self._counts.pop(event_type, None)

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._counts)
