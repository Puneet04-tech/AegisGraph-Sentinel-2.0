"""Security Playbook Service"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime
from .models import Playbook, PlaybookTask, Execution, ExecutionStatus, TaskStatus

class PlaybookService:
    """Security Playbook Automation Service"""
    
    def __init__(self) -> None:
        self.playbooks: Dict[str, Playbook] = {}
        self.executions: Dict[str, Execution] = {}
        self._init_default_playbooks()
    
    def _init_default_playbooks(self) -> None:
        """Initialize default playbooks"""
        playbooks = [
            Playbook(
                playbook_id="pb-001",
                name="Ransomware Response",
                description="Automated ransomware response playbook",
                trigger_type="threat_detected",
                tasks=[
                    PlaybookTask(
                        task_id="task-1",
                        name="Isolate System",
                        action_type="ISOLATE",
                        parameters={"scope": "host"},
                        order=1
                    ),
                    PlaybookTask(
                        task_id="task-2",
                        name="Backup Data",
                        action_type="BACKUP",
                        parameters={"priority": "high"},
                        order=2
                    ),
                    PlaybookTask(
                        task_id="task-3",
                        name="Notify SOC",
                        action_type="NOTIFY",
                        parameters={"channel": "slack"},
                        order=3
                    )
                ]
            )
        ]
        for pb in playbooks:
            self.playbooks[pb.playbook_id] = pb
    
    def create_playbook(
        self,
        name: str,
        description: str,
        trigger_type: str,
        tasks: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create a new playbook"""
        playbook_tasks = [
            PlaybookTask(
                task_id=str(uuid4())[:8],
                name=t["name"],
                action_type=t["action_type"],
                parameters=t.get("parameters", {}),
                order=t["order"],
                requires_approval=t.get("requires_approval", False)
            )
            for t in tasks
        ]
        playbook = Playbook(
            playbook_id=str(uuid4())[:8],
            name=name,
            description=description,
            trigger_type=trigger_type,
            tasks=playbook_tasks
        )
        self.playbooks[playbook.playbook_id] = playbook
        return playbook.to_dict()
    
    def get_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Get a playbook"""
        playbook = self.playbooks.get(playbook_id)
        return playbook.to_dict() if playbook else None
    
    def get_all_playbooks(self) -> List[Dict[str, Any]]:
        """Get all playbooks"""
        return [p.to_dict() for p in self.playbooks.values()]
    
    def run_playbook(self, playbook_id: str) -> Dict[str, Any]:
        """Execute a playbook"""
        playbook = self.playbooks.get(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook {playbook_id} not found")
        
        execution = Execution(
            execution_id=str(uuid4())[:8],
            playbook_id=playbook_id,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.utcnow(),
            current_task=playbook.tasks[0].task_id if playbook.tasks else None
        )
        
        # Simulate execution
        for task in playbook.tasks:
            execution.results.append({
                "task_id": task.task_id,
                "status": "COMPLETED",
                "timestamp": datetime.utcnow().isoformat()
            })
        
        execution.status = ExecutionStatus.COMPLETED
        execution.completed_at = datetime.utcnow()
        execution.current_task = None
        self.executions[execution.execution_id] = execution
        return execution.to_dict()
    
    def get_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get an execution"""
        execution = self.executions.get(execution_id)
        return execution.to_dict() if execution else None
    
    def get_playbook_executions(self, playbook_id: str) -> List[Dict[str, Any]]:
        """Get executions for a playbook"""
        return [e.to_dict() for e in self.executions.values() if e.playbook_id == playbook_id]
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get playbook dashboard"""
        status_counts: Dict[str, int] = {}
        for exec in self.executions.values():
            status_counts[exec.status.value] = status_counts.get(exec.status.value, 0) + 1
        
        return {
            "total_playbooks": len(self.playbooks),
            "total_executions": len(self.executions),
            "executions_by_status": status_counts
        }


_playbook_service: Optional[PlaybookService] = None

def get_playbook_service() -> PlaybookService:
    """Get the global service instance"""
    global _playbook_service
    if _playbook_service is None:
        _playbook_service = PlaybookService()
    return _playbook_service