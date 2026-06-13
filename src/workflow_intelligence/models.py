"""
Security Workflow Intelligence Platform - Data Models

Enterprise-grade workflow intelligence for AegisGraph Sentinel 2.0.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class WorkflowType(str, Enum):
    """Workflow types."""
    INVESTIGATION = "INVESTIGATION"
    FRAUD_REVIEW = "FRAUD_REVIEW"
    COMPLIANCE_AUDIT = "COMPLIANCE_AUDIT"
    THREAT_ANALYSIS = "THREAT_ANALYSIS"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"
    CASE_MANAGEMENT = "CASE_MANAGEMENT"
    GOVERNANCE_REVIEW = "GOVERNANCE_REVIEW"
    OPERATIONAL = "OPERATIONAL"


class WorkflowStatus(str, Enum):
    """Workflow status."""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    ESCALATED = "ESCALATED"


class WorkflowPriority(str, Enum):
    """Workflow priority."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class TaskStatus(str, Enum):
    """Task status."""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"


class Workflow(BaseModel):
    """Security workflow."""
    workflow_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    workflow_type: WorkflowType
    priority: WorkflowPriority = WorkflowPriority.MEDIUM
    status: WorkflowStatus = WorkflowStatus.PENDING
    owner: str = ""
    assignee: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    sla_deadline: Optional[datetime] = None
    estimated_duration_hours: float = 0.0
    actual_duration_hours: float = 0.0
    progress_percentage: float = 0.0
    tasks: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    blocked_by: List[str] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)


class WorkflowTask(BaseModel):
    """Workflow task."""
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    workflow_id: str
    name: str
    description: str = ""
    status: TaskStatus = TaskStatus.PENDING
    assignee: Optional[str] = None
    order: int = 0
    estimated_hours: float = 0.0
    actual_hours: float = 0.0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    dependencies: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SLAMetric(BaseModel):
    """SLA metric."""
    metric_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    workflow_id: str
    sla_type: str
    target_hours: float
    actual_hours: float
    is_met: bool = False
    variance_hours: float = 0.0
    calculated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WorkflowAnalytics(BaseModel):
    """Workflow analytics."""
    analytics_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    workflow_type: WorkflowType
    period_start: datetime
    period_end: datetime
    total_workflows: int = 0
    completed_workflows: int = 0
    avg_completion_time_hours: float = 0.0
    sla_compliance_rate: float = 0.0
    bottleneck_count: int = 0
    resource_utilization: float = 0.0
    throughput: float = 0.0


class OptimizationRecommendation(BaseModel):
    """Workflow optimization recommendation."""
    recommendation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    workflow_id: Optional[str] = None
    recommendation_type: str
    title: str
    description: str
    expected_impact: str
    effort: str = "MEDIUM"
    priority: WorkflowPriority = WorkflowPriority.MEDIUM
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ResourceAllocation(BaseModel):
    """Resource allocation."""
    allocation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    workflow_id: str
    resource_type: str
    resource_id: str
    allocated_hours: float = 0.0
    utilized_hours: float = 0.0
    efficiency: float = 0.0


class WorkflowMetrics(BaseModel):
    """Workflow metrics."""
    total_workflows: int = 0
    active_workflows: int = 0
    completed_workflows: int = 0
    blocked_workflows: int = 0
    sla_met_count: int = 0
    sla_missed_count: int = 0
    avg_completion_time_hours: float = 0.0
    throughput_per_day: float = 0.0
    workflows_by_type: Dict[str, int] = Field(default_factory=dict)
    workflows_by_priority: Dict[str, int] = Field(default_factory=dict)
    bottlenecks: List[Dict[str, Any]] = Field(default_factory=list)
