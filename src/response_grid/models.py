"""Response Grid Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class IncidentStatus(Enum):
    """Incident status"""
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"

class Severity(Enum):
    """Severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class RemediationStatus(Enum):
    """Remediation status"""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

@dataclass
class Incident:
    """Incident definition"""
    incident_id: str
    title: str
    description: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.OPEN
    organization_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    linked_incidents: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "organization_id": self.organization_id,
            "tags": self.tags,
            "linked_incidents": self.linked_incidents,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

@dataclass
class Playbook:
    """Automated response playbook"""
    playbook_id: str
    name: str
    description: str
    steps: List[Dict[str, Any]]
    applicable_severities: List[Severity]
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "steps": self.steps,
            "applicable_severities": [s.value for s in self.applicable_severities],
            "enabled": self.enabled
        }

@dataclass
class RemediationAction:
    """Remediation action record"""
    action_id: str
    incident_id: str
    action_type: str
    description: str
    status: RemediationStatus
    assigned_to: Optional[str] = None
    executed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "incident_id": self.incident_id,
            "action_type": self.action_type,
            "description": self.description,
            "status": self.status.value,
            "assigned_to": self.assigned_to,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "result": self.result
        }

@dataclass
class PartnerOrganization:
    """Partner organization in the response grid"""
    org_id: str
    name: str
    country: str
    trust_level: float = 0.5
    active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "org_id": self.org_id,
            "name": self.name,
            "country": self.country,
            "trust_level": self.trust_level,
            "active": self.active
        }