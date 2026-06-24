"""Security Playbook Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class ExecutionStatus(Enum):
    """Execution status"""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class TaskStatus(Enum):
    """Task status"""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"

@dataclass
class PlaybookTask:
    """Playbook task definition"""
    task_id: str
    name: str
    action_type: str
    parameters: Dict[str, Any]
    order: int
    requires_approval: bool = False
    retry_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "name": self.name,
            "action_type": self.action_type,
            "parameters": self.parameters,
            "order": self.order,
            "requires_approval": self.requires_approval,
            "retry_count": self.retry_count
        }

@dataclass
class Playbook:
    """Security playbook"""
    playbook_id: str
    name: str
    description: str
    trigger_type: str
    tasks: List[PlaybookTask]
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "trigger_type": self.trigger_type,
            "tasks": [t.to_dict() for t in self.tasks],
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat()
        }

@dataclass
class Execution:
    """Playbook execution"""
    execution_id: str
    playbook_id: str
    status: ExecutionStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    current_task: Optional[str] = None
    results: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "playbook_id": self.playbook_id,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "current_task": self.current_task,
            "results": self.results
        }