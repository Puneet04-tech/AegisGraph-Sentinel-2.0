"""
AI Security Agent Swarm Models
Distributed AI agent ecosystem for security operations.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class AgentType(Enum):
    """Types of security agents."""
    FRAUD_AGENT = "FRAUD_AGENT"
    THREAT_HUNTING_AGENT = "THREAT_HUNTING_AGENT"
    AML_AGENT = "AML_AGENT"
    COMPLIANCE_AGENT = "COMPLIANCE_AGENT"
    INVESTIGATION_AGENT = "INVESTIGATION_AGENT"
    FORENSICS_AGENT = "FORENSICS_AGENT"
    RISK_AGENT = "RISK_AGENT"
    RESPONSE_AGENT = "RESPONSE_AGENT"
    INTELLIGENCE_AGENT = "INTELLIGENCE_AGENT"
    SWARM_ORCHESTRATOR = "SWARM_ORCHESTRATOR"


class AgentStatus(Enum):
    """Agent operational status."""
    IDLE = "IDLE"
    BUSY = "BUSY"
    WORKING = "WORKING"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"
    OFFLINE = "OFFLINE"


class TaskPriority(Enum):
    """Task priority levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class TaskStatus(Enum):
    """Task status."""
    PENDING = "PENDING"
    ASSIGNED = "ASSIGNED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass
class Agent:
    """Security agent."""
    agent_id: str
    agent_type: AgentType
    name: str
    status: AgentStatus = AgentStatus.IDLE
    capabilities: List[str] = field(default_factory=list)
    current_task: Optional[str] = None
    tasks_completed: int = 0
    success_rate: float = 0.0
    last_active: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type.value,
            "name": self.name,
            "status": self.status.value,
            "capabilities": self.capabilities,
            "current_task": self.current_task,
            "tasks_completed": self.tasks_completed,
            "success_rate": self.success_rate,
            "last_active": self.last_active.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class Task:
    """Task for agents to execute."""
    task_id: str
    task_type: str
    description: str
    priority: TaskPriority = TaskPriority.MEDIUM
    status: TaskStatus = TaskStatus.PENDING
    assigned_agent: Optional[str] = None
    input_data: Dict[str, Any] = field(default_factory=dict)
    output_data: Optional[Dict[str, Any]] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "description": self.description,
            "priority": self.priority.value,
            "status": self.status.value,
            "assigned_agent": self.assigned_agent,
            "input_data": self.input_data,
            "output_data": self.output_data,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message,
        }


@dataclass
class SwarmIntelligence:
    """Swarm intelligence data."""
    swarm_id: str
    total_agents: int
    active_agents: int
    tasks_completed: int
    avg_success_rate: float
    collaboration_score: float
    emergent_behaviors: List[str] = field(default_factory=list)


@dataclass
class AgentMessage:
    """Message between agents."""
    message_id: str
    from_agent: str
    to_agent: str
    message_type: str
    content: Dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: Optional[str] = None