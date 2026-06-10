"""Dispatcher queue budget accounting."""

from __future__ import annotations

import threading

from .resource_limits import ResourceLimits


class QueueBudget:
    """Tracks queue utilization and overload state."""

    def __init__(self, limits: ResourceLimits | None = None, max_size: int | None = None) -> None:
        self.limits = limits or ResourceLimits()
        self._max_size = max_size or self.limits.max_event_queue_size
        self._current_size = 0
        self._lock = threading.Lock()

    def update(self, current_size: int, max_size: int | None = None) -> None:
        with self._lock:
            self._current_size = max(0, current_size)
            if max_size is not None:
                self._max_size = max(1, max_size)

    @property
    def current_size(self) -> int:
        with self._lock:
            return self._current_size

    @property
    def max_size(self) -> int:
        with self._lock:
            return self._max_size

    @property
    def utilization(self) -> float:
        with self._lock:
            if self._max_size <= 0:
                return 1.0
            return min(1.0, self._current_size / self._max_size)

    def is_overloaded(self) -> bool:
        with self._lock:
            return self._current_size >= self._max_size

