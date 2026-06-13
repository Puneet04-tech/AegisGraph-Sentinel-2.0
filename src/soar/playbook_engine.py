import uuid
import logging
import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from src.soar.models import Playbook, WorkflowExecution, WorkflowState, Incident
from src.soar.store import SOARStore
from src.soar.audit import SOARAuditLogger

logger = logging.getLogger("aegis.soar.playbook_engine")

class PlaybookEngine:
    def __init__(self, store: SOARStore, audit_logger: SOARAuditLogger, workflow_engine=None) -> None:
        self.store = store
        self.audit_logger = audit_logger
        self.workflow_engine = workflow_engine

    def register_playbook(
        self,
        name: str,
        description: str,
        version: str,
        tasks: List[Dict[str, Any]],
        rules: Dict[str, Any]
    ) -> Playbook:
        playbook_id = f"PLAY-{uuid.uuid4().hex[:8].upper()}"
        playbook = Playbook(
            playbook_id=playbook_id,
            name=name,
            description=description,
            version=version,
            tasks=tasks,
            rules=rules,
            status="Active",
            created_at=datetime.now(timezone.utc).isoformat()
        )
        self.store.add_playbook(playbook)
        
        self.audit_logger.log_action(
            action="REGISTER_PLAYBOOK",
            user_id="SYSTEM",
            ip_address="127.0.0.1",
            status="SUCCESS",
            details={"playbook_id": playbook_id, "name": name, "version": version}
        )
        return playbook

    def trigger_playbooks_for_incident(self, incident: Incident) -> List[WorkflowExecution]:
        executions = []
        playbooks = self.store.list_playbooks()
        
        for playbook in playbooks:
            if playbook.status != "Active":
                continue
                
            # Evaluate rules
            should_trigger = False
            rule_severity = playbook.rules.get("severity")
            rule_source = playbook.rules.get("source")
            
            if rule_severity and incident.severity == rule_severity:
                should_trigger = True
            if rule_source and incident.source == rule_source:
                should_trigger = True
            if not rule_severity and not rule_source:
                # Default fallback trigger
                should_trigger = True
                
            if should_trigger:
                execution = self.execute_playbook(playbook.playbook_id, incident.incident_id)
                if execution:
                    executions.append(execution)
                    
        return executions

    def execute_playbook(self, playbook_id: str, incident_id: str) -> Optional[WorkflowExecution]:
        playbook = self.store.get_playbook(playbook_id)
        incident = self.store.get_incident(incident_id)
        if not playbook or not incident:
            return None

        execution_id = f"WF-{uuid.uuid4().hex[:8].upper()}"
        execution = WorkflowExecution(
            execution_id=execution_id,
            playbook_id=playbook_id,
            incident_id=incident_id,
            state=WorkflowState.RUNNING,
            current_task_index=0,
            task_results={},
            start_time=datetime.now(timezone.utc).isoformat()
        )
        
        self.store.add_workflow_execution(execution)
        
        self.audit_logger.log_action(
            action="START_PLAYBOOK_EXECUTION",
            user_id="SYSTEM",
            ip_address="127.0.0.1",
            status="SUCCESS",
            details={"execution_id": execution_id, "playbook_id": playbook_id, "incident_id": incident_id}
        )

        # Dispatch execution task asynchronously
        if self.workflow_engine:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self.workflow_engine.run_workflow(execution))
            except RuntimeError:
                # No running event loop (e.g. sync tests)
                asyncio.run(self.workflow_engine.run_workflow(execution))
        else:
            # Synchronous execution fallback for test environment
            self._execute_sync_fallback(execution, playbook, incident)

        return execution

    def _execute_sync_fallback(self, execution: WorkflowExecution, playbook: Playbook, incident: Incident) -> None:
        try:
            for idx, task in enumerate(playbook.tasks):
                execution.current_task_index = idx
                # Simulate task execution
                task_name = task.get("name", f"Task_{idx}")
                execution.task_results[task_name] = {"status": "SUCCESS", "message": "Executed successfully"}
                
                # Check for simple conditional routing inside task parameters
                # e.g. "conditional_routing": {"if_severity_is": "CRITICAL", "action": "ESCALATE"}
                cond = task.get("conditional_routing")
                if cond:
                    if_sev = cond.get("if_severity_is")
                    if if_sev and incident.severity != if_sev:
                        # Skip next tasks or stop
                        execution.task_results[task_name]["message"] = "Skipped due to condition"
                        break
                        
            execution.state = WorkflowState.COMPLETED
            execution.end_time = datetime.now(timezone.utc).isoformat()
            self.store.update_workflow_execution(execution)
            
            self.audit_logger.log_action(
                action="COMPLETE_PLAYBOOK_EXECUTION",
                user_id="SYSTEM",
                ip_address="127.0.0.1",
                status="SUCCESS",
                details={"execution_id": execution.execution_id, "state": "COMPLETED"}
            )
        except Exception as e:
            execution.state = WorkflowState.FAILED
            execution.end_time = datetime.now(timezone.utc).isoformat()
            self.store.update_workflow_execution(execution)
            
            self.audit_logger.log_action(
                action="FAIL_PLAYBOOK_EXECUTION",
                user_id="SYSTEM",
                ip_address="127.0.0.1",
                status="FAILED",
                details={"execution_id": execution.execution_id, "error": str(e)}
            )
