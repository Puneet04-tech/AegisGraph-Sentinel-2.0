"""Security Universe Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class TeamType(Enum):
    """Security team types"""
    SOC = "SOC"
    FRAUD_OPS = "FRAUD_OPS"
    AML_OPS = "AML_OPS"
    RISK_MANAGEMENT = "RISK_MANAGEMENT"
    COMPLIANCE = "COMPLIANCE"
    GOVERNANCE = "GOVERNANCE"

class WorkflowStatus(Enum):
    """Workflow status"""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"

class IncidentSeverity(Enum):
    """Incident severity levels"""
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"

@dataclass
class Team:
    """Security team definition"""
    team_id: str
    name: str
    team_type: TeamType
    members: List[str]
    responsibilities: List[str]
    contact_email: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "team_id": self.team_id,
            "name": self.name,
            "team_type": self.team_type.value,
            "members": self.members,
            "responsibilities": self.responsibilities,
            "contact_email": self.contact_email
        }

@dataclass
class UnifiedIncident:
    """Cross-team unified incident"""
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    source_teams: List[TeamType]
    assigned_teams: List[TeamType]
    status: WorkflowStatus
    related_incidents: List[str]
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "source_teams": [t.value for t in self.source_teams],
            "assigned_teams": [t.value for t in self.assigned_teams],
            "status": self.status.value,
            "related_incidents": self.related_incidents,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

@dataclass
class CollaborationRecord:
    """Cross-team collaboration record"""
    record_id: str
    incident_id: str
    from_team: TeamType
    to_team: TeamType
    action: str
    notes: str
    created_by: str
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "incident_id": self.incident_id,
            "from_team": self.from_team.value,
            "to_team": self.to_team.value,
            "action": self.action,
            "notes": self.notes,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat()
        }

@dataclass
class Workflow:
    """Cross-team workflow"""
    workflow_id: str
    name: str
    description: str
    teams_involved: List[TeamType]
    steps: List[Dict[str, Any]]
    status: WorkflowStatus

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "name": self.name,
            "description": self.description,
            "teams_involved": [t.value for t in self.teams_involved],
            "steps": self.steps,
            "status": self.status.value
        }