"""Case Workflow Models"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class CaseStatus(Enum):
    """Case status"""
    NEW = "NEW"
    ASSIGNED = "ASSIGNED"
    IN_PROGRESS = "IN_PROGRESS"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    CANCELLED = "CANCELLED"

class Priority(Enum):
    """Case priority"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4

class SLALevel(Enum):
    """SLA levels"""
    P1 = "P1"  # 1 hour response
    P2 = "P2"  # 4 hours
    P3 = "P3"  # 24 hours
    P4 = "P4"  # 72 hours

@dataclass
class Workflow:
    """Workflow definition"""
    workflow_id: str
    name: str
    description: str
    states: List[str]
    transitions: Dict[str, List[str]]
    initial_state: str
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "name": self.name,
            "description": self.description,
            "states": self.states,
            "transitions": self.transitions,
            "initial_state": self.initial_state,
            "enabled": self.enabled
        }

@dataclass
class Case:
    """Case definition"""
    case_id: str
    title: str
    description: str
    workflow_id: str
    current_state: str
    status: CaseStatus
    priority: Priority
    assignee: Optional[str] = None
    escalated_to: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "description": self.description,
            "workflow_id": self.workflow_id,
            "current_state": self.current_state,
            "status": self.status.value,
            "priority": self.priority.name,
            "assignee": self.assignee,
            "escalated_to": self.escalated_to,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

@dataclass
class SLA:
    """SLA definition"""
    sla_id: str
    case_id: str
    sla_level: SLALevel
    due_at: datetime
    breached: bool = False
    breached_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sla_id": self.sla_id,
            "case_id": self.case_id,
            "sla_level": self.sla_level.value,
            "due_at": self.due_at.isoformat(),
            "breached": self.breached,
            "breached_at": self.breached_at.isoformat() if self.breached_at else None
        }

@dataclass
class Escalation:
    """Escalation record"""
    escalation_id: str
    case_id: str
    from_assignee: str
    to_assignee: str
    reason: str
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "escalation_id": self.escalation_id,
            "case_id": self.case_id,
            "from_assignee": self.from_assignee,
            "to_assignee": self.to_assignee,
            "reason": self.reason,
            "created_at": self.created_at.isoformat()
        }

@dataclass
class Assignment:
    """Case assignment"""
    assignment_id: str
    case_id: str
    assignee: str
    assigned_by: str
    assigned_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assignment_id": self.assignment_id,
            "case_id": self.case_id,
            "assignee": self.assignee,
            "assigned_by": self.assigned_by,
            "assigned_at": self.assigned_at.isoformat()
        }