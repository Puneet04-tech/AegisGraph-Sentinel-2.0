"""Control Plane Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class ControlStatus(Enum):
    """Control execution status"""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class ModuleType(Enum):
    """AegisGraph module types"""
    FRAUD = "FRAUD"
    CTI = "CTI"
    GOVERNANCE = "GOVERNANCE"
    RISK = "RISK"
    COMPLIANCE = "COMPLIANCE"
    SOC = "SOC"
    INVESTIGATION = "INVESTIGATION"
    DEFENSE_GRID = "DEFENSE_GRID"
    INTELLIGENCE_EXCHANGE = "INTELLIGENCE_EXCHANGE"

class PolicyType(Enum):
    """Policy types"""
    SECURITY = "SECURITY"
    ACCESS = "ACCESS"
    DATA = "DATA"
    OPERATIONAL = "OPERATIONAL"

@dataclass
class SecurityControl:
    """Security control definition"""
    control_id: str
    name: str
    description: str
    module_type: ModuleType
    policy_type: PolicyType
    enabled: bool = True
    priority: int = 1
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "name": self.name,
            "description": self.description,
            "module_type": self.module_type.value,
            "policy_type": self.policy_type.value,
            "enabled": self.enabled,
            "priority": self.priority,
            "created_at": self.created_at.isoformat()
        }

@dataclass
class ControlExecution:
    """Control execution record"""
    execution_id: str
    control_id: str
    status: ControlStatus
    module_type: ModuleType
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "control_id": self.control_id,
            "status": self.status.value,
            "module_type": self.module_type.value,
            "result": self.result,
            "error": self.error,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None
        }

@dataclass
class Workflow:
    """Global workflow definition"""
    workflow_id: str
    name: str
    description: str
    steps: List[Dict[str, Any]]
    modules_involved: List[ModuleType]
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "name": self.name,
            "description": self.description,
            "steps": self.steps,
            "modules_involved": [m.value for m in self.modules_involved],
            "enabled": self.enabled
        }

@dataclass
class PlatformHealth:
    """Platform health status"""
    module_type: ModuleType
    status: str
    uptime: float
    last_heartbeat: datetime
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module_type": self.module_type.value,
            "status": self.status,
            "uptime": self.uptime,
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "errors": self.errors
        }