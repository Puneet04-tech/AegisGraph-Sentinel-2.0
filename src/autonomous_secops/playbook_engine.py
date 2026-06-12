"""
Response Playbook Engine.

Manages automated response playbooks.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import Playbook, PlaybookExecution, PlaybookStatus, Severity
from .store import AutonomousSecOpsStore, get_secops_store


class PlaybookEngine:
    """Engine for response playbooks."""

    def __init__(self, store: Optional[AutonomousSecOpsStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_secops_store()

    def create_playbook(
        self,
        name: str,
        description: str,
        trigger_conditions: Dict[str, Any],
        steps: List[Dict[str, Any]],
    ) -> Playbook:
        """Create a response playbook."""
        playbook_id = f"playbook-{uuid.uuid4().hex[:12]}"
        
        playbook = Playbook(
            playbook_id=playbook_id,
            name=name,
            description=description,
            trigger_conditions=trigger_conditions,
            steps=steps,
        )
        
        self.store.add_playbook(playbook)
        
        self.store.log_audit(
            user_id="system",
            action="playbook_created",
            resource_type="playbook",
            resource_id=playbook_id,
            details={"name": name},
        )
        
        return playbook

    def get_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Get playbook details."""
        playbook = self.store.get_playbook(playbook_id)
        if not playbook:
            return None
        
        return {
            "playbook_id": playbook.playbook_id,
            "name": playbook.name,
            "description": playbook.description,
            "steps": playbook.steps,
            "status": playbook.status.value,
            "executed_count": playbook.executed_count,
            "success_rate": playbook.success_rate,
        }

    def get_all_playbooks(self) -> List[Dict[str, Any]]:
        """Get all playbooks."""
        playbooks = list(self.store._playbooks.values())
        return [
            {
                "playbook_id": p.playbook_id,
                "name": p.name,
                "description": p.description,
                "status": p.status.value,
                "executed_count": p.executed_count,
            }
            for p in playbooks
        ]

    def execute_playbook(
        self,
        playbook_id: str,
        incident_id: str,
    ) -> PlaybookExecution:
        """Execute a playbook."""
        playbook = self.store.get_playbook(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook not found: {playbook_id}")
        
        execution_id = f"exec-{uuid.uuid4().hex[:12]}"
        
        execution = PlaybookExecution(
            execution_id=execution_id,
            playbook_id=playbook_id,
            incident_id=incident_id,
            status="executing",
        )
        
        self.store.create_playbook_execution(execution)
        
        playbook.executed_count += 1
        playbook.status = PlaybookStatus.EXECUTING
        
        self.store.log_audit(
            user_id="system",
            action="playbook_execution_started",
            resource_type="playbook_execution",
            resource_id=execution_id,
            details={"playbook_id": playbook_id, "incident_id": incident_id},
        )
        
        return execution

    def execute_step(
        self,
        execution_id: str,
        step_index: int,
        result: Dict[str, Any],
    ) -> bool:
        """Record step execution result."""
        execution = self.store.get_playbook_execution(execution_id)
        if not execution:
            return False
        
        execution.results.append({
            "step_index": step_index,
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        
        execution.current_step = step_index + 1
        
        return True

    def complete_execution(
        self,
        execution_id: str,
        success: bool = True,
    ) -> bool:
        """Complete playbook execution."""
        execution = self.store.get_playbook_execution(execution_id)
        if not execution:
            return False
        
        execution.status = "completed" if success else "failed"
        execution.completed_at = datetime.now(timezone.utc)
        
        playbook = self.store.get_playbook(execution.playbook_id)
        if playbook:
            playbook.status = PlaybookStatus.COMPLETED if success else PlaybookStatus.FAILED
            
            total = playbook.executed_count
            if total > 0:
                success_count = sum(
                    1 for e in self.store._playbook_executions.values()
                    if e.playbook_id == playbook.playbook_id and e.status == "completed"
                )
                playbook.success_rate = success_count / total
        
        self.store.log_audit(
            user_id="system",
            action="playbook_execution_completed",
            resource_type="playbook_execution",
            resource_id=execution_id,
            details={"success": success},
        )
        
        return True

    def get_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get execution details."""
        execution = self.store.get_playbook_execution(execution_id)
        if not execution:
            return None
        
        return {
            "execution_id": execution.execution_id,
            "playbook_id": execution.playbook_id,
            "incident_id": execution.incident_id,
            "status": execution.status,
            "current_step": execution.current_step,
            "results": execution.results,
            "started_at": execution.started_at.isoformat(),
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
        }


# Singleton instance
_engine: Optional[PlaybookEngine] = None


def get_playbook_engine() -> PlaybookEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = PlaybookEngine()
    return _engine


def reset_playbook_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None