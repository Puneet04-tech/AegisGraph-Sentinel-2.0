"""
Security Workflow Intelligence Store - Thread-safe storage
"""

from __future__ import annotations

from threading import Lock
from typing import Any, Dict, List, Optional

from .models import (
    Workflow,
    WorkflowTask,
    SLAMetric,
    WorkflowAnalytics,
    OptimizationRecommendation,
    ResourceAllocation,
    WorkflowType,
    WorkflowStatus,
    WorkflowPriority,
)


class WorkflowStore:
    """Thread-safe storage for workflow data."""

    def __init__(self):
        self._lock = Lock()
        self._workflows: Dict[str, Workflow] = {}
        self._tasks: Dict[str, WorkflowTask] = {}
        self._sla_metrics: Dict[str, SLAMetric] = {}
        self._analytics: Dict[str, WorkflowAnalytics] = {}
        self._recommendations: Dict[str, OptimizationRecommendation] = {}
        self._allocations: Dict[str, ResourceAllocation] = {}

    def store_workflow(self, workflow: Workflow) -> Workflow:
        with self._lock:
            self._workflows[workflow.workflow_id] = workflow
        return workflow

    def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        return self._workflows.get(workflow_id)

    def get_workflows_by_type(
        self, workflow_type: WorkflowType
    ) -> List[Workflow]:
        return [
            w for w in self._workflows.values()
            if w.workflow_type == workflow_type
        ]

    def get_workflows_by_status(
        self, status: WorkflowStatus
    ) -> List[Workflow]:
        return [
            w for w in self._workflows.values()
            if w.status == status
        ]

    def get_workflows_by_priority(
        self, priority: WorkflowPriority
    ) -> List[Workflow]:
        return [
            w for w in self._workflows.values()
            if w.priority == priority
        ]

    def get_all_workflows(self) -> List[Workflow]:
        return list(self._workflows.values())

    def get_active_workflows(self) -> List[Workflow]:
        return [
            w for w in self._workflows.values()
            if w.status in [WorkflowStatus.PENDING, WorkflowStatus.IN_PROGRESS]
        ]

    def store_task(self, task: WorkflowTask) -> WorkflowTask:
        with self._lock:
            self._tasks[task.task_id] = task
        return task

    def get_task(self, task_id: str) -> Optional[WorkflowTask]:
        return self._tasks.get(task_id)

    def get_tasks_by_workflow(
        self, workflow_id: str
    ) -> List[WorkflowTask]:
        return [
            t for t in self._tasks.values()
            if t.workflow_id == workflow_id
        ]

    def store_sla_metric(self, metric: SLAMetric) -> SLAMetric:
        with self._lock:
            self._sla_metrics[metric.metric_id] = metric
        return metric

    def get_sla_metrics_by_workflow(
        self, workflow_id: str
    ) -> List[SLAMetric]:
        return [
            m for m in self._sla_metrics.values()
            if m.workflow_id == workflow_id
        ]

    def store_analytics(
        self, analytics: WorkflowAnalytics
    ) -> WorkflowAnalytics:
        with self._lock:
            self._analytics[analytics.analytics_id] = analytics
        return analytics

    def get_analytics_by_type(
        self, workflow_type: WorkflowType
    ) -> List[WorkflowAnalytics]:
        return [
            a for a in self._analytics.values()
            if a.workflow_type == workflow_type
        ]

    def store_recommendation(
        self, recommendation: OptimizationRecommendation
    ) -> OptimizationRecommendation:
        with self._lock:
            self._recommendations[recommendation.recommendation_id] = recommendation
        return recommendation

    def get_all_recommendations(self) -> List[OptimizationRecommendation]:
        return list(self._recommendations.values())

    def store_allocation(
        self, allocation: ResourceAllocation
    ) -> ResourceAllocation:
        with self._lock:
            self._allocations[allocation.allocation_id] = allocation
        return allocation

    def get_allocations_by_workflow(
        self, workflow_id: str
    ) -> List[ResourceAllocation]:
        return [
            a for a in self._allocations.values()
            if a.workflow_id == workflow_id
        ]

    def get_metrics(self) -> Dict[str, Any]:
        workflows = list(self._workflows.values())
        type_counts: Dict[str, int] = {}
        priority_counts: Dict[str, int] = {}

        for w in workflows:
            type_counts[w.workflow_type.value] = (
                type_counts.get(w.workflow_type.value, 0) + 1
            )
            priority_counts[w.priority.value] = (
                priority_counts.get(w.priority.value, 0) + 1
            )

        sla_metrics = list(self._sla_metrics.values())
        sla_met = len([m for m in sla_metrics if m.is_met])

        return {
            "total_workflows": len(workflows),
            "active_workflows": len(self.get_active_workflows()),
            "completed_workflows": len(self.get_workflows_by_status(WorkflowStatus.COMPLETED)),
            "blocked_workflows": len(self.get_workflows_by_status(WorkflowStatus.BLOCKED)),
            "sla_met_count": sla_met,
            "sla_missed_count": len(sla_metrics) - sla_met,
            "workflows_by_type": type_counts,
            "workflows_by_priority": priority_counts,
        }


_workflow_store: Optional[WorkflowStore] = None
_store_lock = Lock()


def get_workflow_store() -> WorkflowStore:
    global _workflow_store
    with _store_lock:
        if _workflow_store is None:
            _workflow_store = WorkflowStore()
        return _workflow_store


def reset_workflow_store() -> None:
    global _workflow_store
    with _store_lock:
        _workflow_store = WorkflowStore()
