"""Runtime resource governance facade."""

from __future__ import annotations

import logging
from typing import Any, Dict

from ...audit import log_audit_event
from .backpressure import BackpressureController
from .queue_budget import QueueBudget
from .resource_limits import ResourceLimits
from .task_budget import TaskBudget

logger = logging.getLogger(__name__)


def _audit_resource_event(event_type: str, **metadata: Any) -> None:
    try:
        log_audit_event(
            event_type=event_type,
            severity="warning",
            source="resource_manager",
            metadata=metadata,
        )
    except Exception:
        logger.debug("Resource audit recording failed", exc_info=True)


class RuntimeResourceManager:
    """Owns lightweight budgets and exposes resource decisions/metrics."""

    def __init__(self, limits: ResourceLimits | None = None) -> None:
        self.limits = limits or ResourceLimits()
        self.task_budget = TaskBudget(self.limits)
        self.queue_budget = QueueBudget(self.limits)
        self.backpressure = BackpressureController(self.limits)

    def register_task(self, task_id: Any) -> bool:
        accepted = self.task_budget.register_task(task_id)
        if not accepted:
            logger.warning("Runtime task registration denied by resource budget")
            _audit_resource_event("resource_task_registration_throttled")
        return accepted

    def unregister_task(self, task_id: Any) -> None:
        self.task_budget.unregister_task(task_id)

    def update_queue_size(self, current_size: int, max_size: int | None = None) -> None:
        self.queue_budget.update(current_size, max_size)

    def can_accept_event(self) -> bool:
        accepted = self.backpressure.can_accept_event(
            queue_utilization=self.queue_budget.utilization,
            task_budget_exceeded=self.task_budget.is_exceeded(),
        )
        if not accepted:
            logger.warning(
                "Runtime event denied by backpressure: queue_utilization=%.2f event_rate=%s",
                self.queue_budget.utilization,
                self.backpressure.event_rate,
            )
            _audit_resource_event(
                "resource_event_throttled",
                queue_utilization=self.queue_budget.utilization,
                event_rate=self.backpressure.event_rate,
            )
        return accepted

    def can_start_recovery(self) -> bool:
        accepted = self.backpressure.can_start_recovery()
        if not accepted:
            logger.warning(
                "Runtime recovery denied by backpressure: recovery_rate=%s",
                self.backpressure.recovery_rate,
            )
            _audit_resource_event(
                "resource_recovery_throttled",
                recovery_rate=self.backpressure.recovery_rate,
            )
        return accepted

    def get_resource_metrics(self) -> Dict[str, Any]:
        return {
            "active_tasks": self.task_budget.current_count,
            "queue_size": self.queue_budget.current_size,
            "queue_max_size": self.queue_budget.max_size,
            "queue_utilization": self.queue_budget.utilization,
            "backpressure_state": self.backpressure.state,
            "event_rate": self.backpressure.event_rate,
            "recovery_rate": self.backpressure.recovery_rate,
            "memory_warning_threshold_mb": self.limits.memory_warning_threshold_mb,
        }

