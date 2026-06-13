"""
Security Workflow Intelligence Service - Core business logic
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from .models import (
    Workflow,
    WorkflowTask,
    SLAMetric,
    WorkflowAnalytics,
    OptimizationRecommendation,
    ResourceAllocation,
    WorkflowMetrics,
    WorkflowType,
    WorkflowStatus,
    WorkflowPriority,
    TaskStatus,
)
from .store import get_workflow_store, WorkflowStore, reset_workflow_store


class WorkflowService:
    """Core workflow intelligence service."""

    def __init__(self, store: Optional[WorkflowStore] = None):
        self._store = store or get_workflow_store()

    def create_workflow(
        self,
        name: str,
        description: str,
        workflow_type: WorkflowType,
        priority: WorkflowPriority = WorkflowPriority.MEDIUM,
        owner: str = "",
        sla_hours: Optional[float] = None,
        **kwargs: Any,
    ) -> Workflow:
        """Create a new workflow."""
        workflow = Workflow(
            name=name,
            description=description,
            workflow_type=workflow_type,
            priority=priority,
            owner=owner,
            **kwargs,
        )
        if sla_hours:
            workflow.sla_deadline = datetime.now(timezone.utc) + timedelta(hours=sla_hours)
        self._store.store_workflow(workflow)
        return workflow

    def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """Get workflow by ID."""
        return self._store.get_workflow(workflow_id)

    def get_workflows(
        self,
        workflow_type: Optional[WorkflowType] = None,
        status: Optional[WorkflowStatus] = None,
        priority: Optional[WorkflowPriority] = None,
    ) -> List[Workflow]:
        """Get workflows with filters."""
        workflows = self._store.get_all_workflows()

        if workflow_type:
            workflows = [w for w in workflows if w.workflow_type == workflow_type]
        if status:
            workflows = [w for w in workflows if w.status == status]
        if priority:
            workflows = [w for w in workflows if w.priority == priority]

        return workflows

    def start_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """Start a workflow."""
        workflow = self._store.get_workflow(workflow_id)
        if workflow:
            workflow.status = WorkflowStatus.IN_PROGRESS
            workflow.started_at = datetime.now(timezone.utc)
            self._store.store_workflow(workflow)
        return workflow

    def complete_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """Complete a workflow."""
        workflow = self._store.get_workflow(workflow_id)
        if workflow:
            workflow.status = WorkflowStatus.COMPLETED
            workflow.completed_at = datetime.now(timezone.utc)
            if workflow.started_at:
                delta = workflow.completed_at - workflow.started_at
                workflow.actual_duration_hours = delta.total_seconds() / 3600
            workflow.progress_percentage = 100.0
            self._store.store_workflow(workflow)
            self._track_sla(workflow)
        return workflow

    def block_workflow(self, workflow_id: str, reason: str = "") -> Optional[Workflow]:
        """Block a workflow."""
        workflow = self._store.get_workflow(workflow_id)
        if workflow:
            workflow.status = WorkflowStatus.BLOCKED
            workflow.metadata["block_reason"] = reason
            self._store.store_workflow(workflow)
        return workflow

    def _track_sla(self, workflow: Workflow) -> None:
        """Track SLA for a workflow."""
        if workflow.sla_deadline and workflow.completed_at:
            target_hours = (workflow.sla_deadline - workflow.created_at).total_seconds() / 3600
            actual_hours = (workflow.completed_at - workflow.created_at).total_seconds() / 3600
            metric = SLAMetric(
                workflow_id=workflow.workflow_id,
                sla_type="completion",
                target_hours=target_hours,
                actual_hours=actual_hours,
                is_met=actual_hours <= target_hours,
                variance_hours=actual_hours - target_hours,
            )
            self._store.store_sla_metric(metric)

    def add_task(
        self,
        workflow_id: str,
        name: str,
        description: str = "",
        assignee: Optional[str] = None,
        estimated_hours: float = 0.0,
        **kwargs: Any,
    ) -> Optional[WorkflowTask]:
        """Add a task to a workflow."""
        workflow = self._store.get_workflow(workflow_id)
        if not workflow:
            return None

        tasks = self._store.get_tasks_by_workflow(workflow_id)
        task = WorkflowTask(
            workflow_id=workflow_id,
            name=name,
            description=description,
            assignee=assignee,
            estimated_hours=estimated_hours,
            order=len(tasks),
            **kwargs,
        )
        self._store.store_task(task)
        return task

    def get_tasks(self, workflow_id: str) -> List[WorkflowTask]:
        """Get tasks for a workflow."""
        return self._store.get_tasks_by_workflow(workflow_id)

    def complete_task(self, task_id: str) -> Optional[WorkflowTask]:
        """Complete a task."""
        task = self._store.get_task(task_id)
        if task:
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now(timezone.utc)
            self._store.store_task(task)
            self._update_workflow_progress(task.workflow_id)
        return task

    def _update_workflow_progress(self, workflow_id: str) -> None:
        """Update workflow progress based on tasks."""
        workflow = self._store.get_workflow(workflow_id)
        if not workflow:
            return

        tasks = self._store.get_tasks_by_workflow(workflow_id)
        if tasks:
            completed = len([t for t in tasks if t.status == TaskStatus.COMPLETED])
            workflow.progress_percentage = (completed / len(tasks)) * 100
            self._store.store_workflow(workflow)

    def predict_sla(
        self,
        workflow_id: str,
        additional_tasks: int = 0,
    ) -> Dict[str, Any]:
        """Predict SLA completion for a workflow."""
        workflow = self._store.get_workflow(workflow_id)
        if not workflow:
            return {}

        tasks = self._store.get_tasks_by_workflow(workflow_id)
        total_hours = sum(t.estimated_hours for t in tasks) + (additional_tasks * 2)
        completed_hours = sum(
            t.actual_hours for t in tasks
            if t.status == TaskStatus.COMPLETED
        )
        remaining_hours = total_hours - completed_hours

        predicted_completion = datetime.now(timezone.utc) + timedelta(hours=remaining_hours)

        return {
            "workflow_id": workflow_id,
            "total_estimated_hours": total_hours,
            "completed_hours": completed_hours,
            "remaining_hours": remaining_hours,
            "predicted_completion": predicted_completion.isoformat(),
            "sla_deadline": workflow.sla_deadline.isoformat() if workflow.sla_deadline else None,
            "on_track": (
                workflow.sla_deadline and
                predicted_completion <= workflow.sla_deadline
            ),
        }

    def identify_bottlenecks(self) -> List[Dict[str, Any]]:
        """Identify workflow bottlenecks."""
        bottlenecks = []

        blocked = self._store.get_workflows_by_status(WorkflowStatus.BLOCKED)
        if blocked:
            bottlenecks.append({
                "type": "blocked_workflows",
                "count": len(blocked),
                "severity": "high",
                "description": f"{len(blocked)} workflows are blocked",
            })

        old_pending = [
            w for w in self._store.get_workflows_by_status(WorkflowStatus.PENDING)
            if (datetime.now(timezone.utc) - w.created_at).days > 7
        ]
        if old_pending:
            bottlenecks.append({
                "type": "stale_workflows",
                "count": len(old_pending),
                "severity": "medium",
                "description": f"{len(old_pending)} workflows pending for over 7 days",
            })

        long_running = [
            w for w in self._store.get_active_workflows()
            if w.started_at and (datetime.now(timezone.utc) - w.started_at).days > 14
        ]
        if long_running:
            bottlenecks.append({
                "type": "long_running",
                "count": len(long_running),
                "severity": "medium",
                "description": f"{len(long_running)} workflows running for over 14 days",
            })

        return bottlenecks

    def recommend_optimization(
        self,
        workflow_id: Optional[str] = None,
    ) -> List[OptimizationRecommendation]:
        """Generate workflow optimization recommendations."""
        recommendations = []
        bottlenecks = self.identify_bottlenecks()

        for bottleneck in bottlenecks:
            if bottleneck["type"] == "blocked_workflows":
                recommendations.append(OptimizationRecommendation(
                    workflow_id=workflow_id,
                    recommendation_type="unblock",
                    title="Resolve Blocked Workflows",
                    description="Review and resolve blocked workflows to improve throughput",
                    expected_impact="Reduce backlog and improve SLA compliance",
                    priority=WorkflowPriority.HIGH,
                ))

        active_workflows = self._store.get_active_workflows()
        if active_workflows:
            avg_age = sum(
                (datetime.now(timezone.utc) - w.created_at).days
                for w in active_workflows
            ) / len(active_workflows)
            if avg_age > 5:
                recommendations.append(OptimizationRecommendation(
                    recommendation_type="process_improvement",
                    title="Improve Workflow Processing Speed",
                    description=f"Average workflow age is {avg_age:.1f} days",
                    expected_impact="Reduce processing time and improve efficiency",
                    effort="MEDIUM",
                    priority=WorkflowPriority.MEDIUM,
                ))

        for rec in recommendations:
            self._store.store_recommendation(rec)

        return recommendations

    def allocate_resource(
        self,
        workflow_id: str,
        resource_type: str,
        resource_id: str,
        hours: float,
    ) -> Optional[ResourceAllocation]:
        """Allocate resources to a workflow."""
        workflow = self._store.get_workflow(workflow_id)
        if not workflow:
            return None

        allocation = ResourceAllocation(
            workflow_id=workflow_id,
            resource_type=resource_type,
            resource_id=resource_id,
            allocated_hours=hours,
        )
        self._store.store_allocation(allocation)
        return allocation

    def get_analytics(
        self,
        workflow_type: Optional[WorkflowType] = None,
    ) -> List[WorkflowAnalytics]:
        """Get workflow analytics."""
        if workflow_type:
            return self._store.get_analytics_by_type(workflow_type)
        return []

    def get_metrics(self) -> WorkflowMetrics:
        """Get workflow metrics."""
        metrics_dict = self._store.get_metrics()
        bottlenecks = self.identify_bottlenecks()

        workflows = self._store.get_all_workflows()
        completed = [
            w for w in workflows
            if w.status == WorkflowStatus.COMPLETED and w.actual_duration_hours > 0
        ]
        avg_completion = (
            sum(w.actual_duration_hours for w in completed) / len(completed)
            if completed else 0.0
        )

        all_workflows = self._store.get_all_workflows()
        days_active = 1
        if all_workflows:
            min_date = min(w.created_at for w in all_workflows)
            days_active = max(1, (datetime.now(timezone.utc) - min_date).days)

        return WorkflowMetrics(
            total_workflows=metrics_dict["total_workflows"],
            active_workflows=metrics_dict["active_workflows"],
            completed_workflows=metrics_dict["completed_workflows"],
            blocked_workflows=metrics_dict["blocked_workflows"],
            sla_met_count=metrics_dict["sla_met_count"],
            sla_missed_count=metrics_dict["sla_missed_count"],
            avg_completion_time_hours=avg_completion,
            throughput_per_day=len(completed) / days_active,
            workflows_by_type=metrics_dict["workflows_by_type"],
            workflows_by_priority=metrics_dict["workflows_by_priority"],
            bottlenecks=bottlenecks,
        )

    def clear(self) -> None:
        """Clear all data."""
        reset_workflow_store()


_workflow_service: Optional[WorkflowService] = None


def get_workflow_service() -> WorkflowService:
    global _workflow_service
    if _workflow_service is None:
        _workflow_service = WorkflowService()
    return _workflow_service


def reset_workflow_service() -> None:
    global _workflow_service
    _workflow_service = None
    reset_workflow_store()
