"""Lightweight active-task admission budget."""

from __future__ import annotations

import logging
import threading
from typing import Any, Set

from .resource_limits import ResourceLimits

logger = logging.getLogger(__name__)


class TaskBudget:
    """Tracks active runtime tasks without managing their lifecycle."""

    def __init__(self, limits: ResourceLimits | None = None) -> None:
        self.limits = limits or ResourceLimits()
        self._active: Set[Any] = set()
        self._lock = threading.RLock()

    def register_task(self, task_id: Any) -> bool:
        with self._lock:
            if len(self._active) >= self.limits.max_runtime_tasks:
                logger.warning(
                    "Runtime task budget exceeded: active=%s max=%s",
                    len(self._active),
                    self.limits.max_runtime_tasks,
                )
                return False
            self._active.add(task_id)
            return True

    def unregister_task(self, task_id: Any) -> None:
        with self._lock:
            self._active.discard(task_id)

    def is_exceeded(self) -> bool:
        return self.current_count >= self.limits.max_runtime_tasks

    @property
    def current_count(self) -> int:
        with self._lock:
            return len(self._active)

