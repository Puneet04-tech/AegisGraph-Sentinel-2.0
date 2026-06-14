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
        self._config_registry: Any = None
        self._policy_engine: Any = None

    def set_config_registry(self, registry: Any) -> None:
        self._config_registry = registry

    def set_policy_engine(self, policy_engine: Any) -> None:
        self._policy_engine = policy_engine

    def _resource_policy_allows(self, **context: Any) -> bool:
        if self._policy_engine is None:
            return True
        result = self._policy_engine.evaluate("resource_throttled", context)
        if result.allowed:
            return True
        logger.warning("Runtime resource admission denied by policy: %s", result.reason)
        _audit_resource_event("policy_violation", policy=result.policy_name, reason=result.reason)
        return False

    def register_task(self, task_id: Any) -> bool:
        if not self._resource_policy_allows(
            resource="task",
            active_tasks=self.task_budget.current_count,
            max_tasks=self.limits.max_runtime_tasks,
            resource_throttled=self.task_budget.current_count >= self.limits.max_runtime_tasks,
            backpressure_state=self.backpressure.state,
        ):
            return False
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
        if not self._resource_policy_allows(
            resource="event",
            queue_utilization=self.queue_budget.utilization,
            task_budget_exceeded=self.task_budget.is_exceeded(),
            resource_throttled=self.queue_budget.is_overloaded() or self.task_budget.is_exceeded(),
            backpressure_state=self.backpressure.state,
        ):
            return False
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
            "configuration_count": len(self._config_registry.list_configs()) if self._config_registry else 0,
        }

