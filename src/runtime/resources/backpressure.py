"""Small backpressure decision controller."""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque

from .resource_limits import ResourceLimits


class BackpressureController:
    """Makes resource admission decisions without blocking or sleeping."""

    HEALTHY = "healthy"
    WARNING = "warning"
    THROTTLED = "throttled"

    def __init__(self, limits: ResourceLimits | None = None) -> None:
        self.limits = limits or ResourceLimits()
        self._events: Deque[float] = deque()
        self._recoveries: Deque[float] = deque()
        self._state = self.HEALTHY
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def can_accept_event(self, *, queue_utilization: float, task_budget_exceeded: bool = False) -> bool:
        with self._lock:
            self._prune(self._events)
            if (
                len(self._events) >= self.limits.max_events_per_window
                or queue_utilization >= 1.0
                or task_budget_exceeded
            ):
                self._state = self.THROTTLED
                return False

            self._events.append(time.monotonic())
            self._state = self.WARNING if queue_utilization >= 0.8 else self.HEALTHY
            return True

    def can_start_recovery(self) -> bool:
        with self._lock:
            self._prune(self._recoveries)
            if len(self._recoveries) >= self.limits.max_recovery_attempts_per_window:
                self._state = self.THROTTLED
                return False

            self._recoveries.append(time.monotonic())
            if self._state != self.THROTTLED:
                warning_at = self.limits.max_recovery_attempts_per_window - 1
                self._state = self.WARNING if len(self._recoveries) >= warning_at else self.HEALTHY
            return True

    @property
    def event_rate(self) -> int:
        with self._lock:
            self._prune(self._events)
            return len(self._events)

    @property
    def recovery_rate(self) -> int:
        with self._lock:
            self._prune(self._recoveries)
            return len(self._recoveries)

    def _prune(self, values: Deque[float]) -> None:
        cutoff = time.monotonic() - self.limits.window_seconds
        while values and values[0] < cutoff:
            values.popleft()
