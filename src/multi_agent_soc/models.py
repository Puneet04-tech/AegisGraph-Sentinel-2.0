"""
Multi-Agent Fraud Security Operations Center Models.

Data models for the SOC framework including agents, tasks, and orchestration.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid


class AgentType(str, Enum):
    """Types of SOC agents."""
    INVESTIGATION = "INVESTIGATION"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    FORENSICS = "FORENSICS"
    FRAUD_RING = "FRAUD_RING"
    REPORTING = "REPORTING"


class AgentStatus(str, Enum):
    """Agent status states."""
    IDLE = "IDLE"
    WORKING = "WORKING"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class TaskPriority(str, Enum):
    """Task priority levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class TaskStatus(str, Enum):
    """Task status states."""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    WAITING_FOR_INPUT = "WAITING_FOR_INPUT"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class InvestigationStatus(str, Enum):
    """Investigation status."""
    NEW = "NEW"
    IN_PROGRESS = "IN_PROGRESS"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"
    ESCALATED = "ESCALATED"
    CLOSED = "CLOSED"


class AgentTask(BaseModel):
    """Task assigned to an agent."""
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_type: AgentType
    title: str
    description: str
    priority: TaskPriority = TaskPriority.MEDIUM
    status: TaskStatus = TaskStatus.PENDING
    parent_task_id: Optional[str] = None
    depends_on: List[str] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    assigned_agent: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary."""
        return {
            "task_id": self.task_id,
            "agent_type": self.agent_type.value,
            "title": self.title,
            "description": self.description,
            "priority": self.priority.value,
            "status": self.status.value,
            "parent_task_id": self.parent_task_id,
            "depends_on": self.depends_on,
            "context": self.context,
            "assigned_agent": self.assigned_agent,
            "result": self.result,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class AgentState(BaseModel):
    """State of a SOC agent."""
    agent_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_type: AgentType
    name: str
    status: AgentStatus = AgentStatus.IDLE
    current_task_id: Optional[str] = None
    completed_tasks: List[str] = Field(default_factory=list)
    capabilities: List[str] = Field(default_factory=list)
    performance_metrics: Dict[str, float] = Field(default_factory=dict)
    memory: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_active: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class InvestigationRequest(BaseModel):
    """Request for fraud investigation."""
    entity_id: Optional[str] = None
    case_id: Optional[str] = None
    alert_ids: List[str] = Field(default_factory=list)
    priority: TaskPriority = TaskPriority.MEDIUM
    context: Dict[str, Any] = Field(default_factory=dict)
    assigned_team: Optional[str] = None


class InvestigationResult(BaseModel):
    """Result of a fraud investigation."""
    investigation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str
    case_id: Optional[str] = None
    status: InvestigationStatus
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    risk_score: float
    recommendations: List[str] = Field(default_factory=list)
    linked_entities: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: float
    processed_by: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None


class ThreatIntelligenceReport(BaseModel):
    """Threat intelligence report."""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    threat_type: str
    threat_actors: List[str] = Field(default_factory=list)
    indicators: List[Dict[str, Any]] = Field(default_factory=list)
    ttps: List[str] = Field(default_factory=list)  # MITRE ATT&CK techniques
    affected_entities: List[str] = Field(default_factory=list)
    confidence: float
    severity: str
    description: str
    recommendations: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ForensicAnalysis(BaseModel):
    """Digital forensics analysis result."""
    analysis_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_entity_id: str
    analysis_type: str
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    artifacts: List[Dict[str, Any]] = Field(default_factory=list)
    timeline_events: List[Dict[str, Any]] = Field(default_factory=list)
    chain_of_custody: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_integrity_hash: Optional[str] = None
    conclusion: str
    confidence: float
    examiner: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FraudRingAnalysis(BaseModel):
    """Fraud ring analysis result."""
    ring_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ring_name: Optional[str] = None
    member_entities: List[str] = Field(default_factory=list)
    relationships: List[Dict[str, Any]] = Field(default_factory=list)
    ring_score: float
    ring_type: str
    financial_impact: float
    geographic_footprint: List[str] = Field(default_factory=list)
    known_techniques: List[str] = Field(default_factory=list)
    connected_campaigns: List[str] = Field(default_factory=list)
    confidence: float
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SOCReport(BaseModel):
    """SOC summary report."""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    report_type: str
    period_start: datetime
    period_end: datetime
    summary: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, float] = Field(default_factory=dict)
    threats_identified: List[Dict[str, Any]] = Field(default_factory=list)
    investigations_summary: Dict[str, Any] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)
    generated_by: str = "REPORTING_AGENT"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AgentMessage(BaseModel):
    """Message between agents."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    from_agent: str
    to_agent: str
    message_type: str
    content: Dict[str, Any]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reply_to: Optional[str] = None


class OrchestrationPlan(BaseModel):
    """Plan for orchestrating multiple agents."""
    plan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    tasks: List[AgentTask] = Field(default_factory=list)
    parallel_groups: List[List[str]] = Field(default_factory=list)  # Task IDs that can run in parallel
    estimated_duration_seconds: int
    priority: TaskPriority = TaskPriority.MEDIUM
    status: str = "PENDING"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


# Store singleton
_store = None


def get_soc_store():
    """Get or create the SOC store singleton."""
    global _store
    if _store is None:
        from .store import SOCStore
        _store = SOCStore()
    return _store