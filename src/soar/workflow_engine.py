import logging
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from src.soar.models import WorkflowExecution, WorkflowState, Playbook, ActionStatus
from src.soar.store import SOARStore
from src.soar.audit import SOARAuditLogger

logger = logging.getLogger("aegis.soar.workflow_engine")

class WorkflowEngine:
    def __init__(self, store: SOARStore, audit_logger: SOARAuditLogger, response_engine=None, enrichment_engine=None, containment_engine=None, notification_engine=None) -> None:
        self.store = store
        self.audit_logger = audit_logger
        self.response_engine = response_engine
        self.enrichment_engine = enrichment_engine
        self.containment_engine = containment_engine
        self.notification_engine = notification_engine

    async def run_workflow(self, execution: WorkflowExecution) -> None:
        playbook = self.store.get_playbook(execution.playbook_id)
        incident = self.store.get_incident(execution.incident_id)
        
        if not playbook or not incident:
            execution.state = WorkflowState.FAILED
            execution.end_time = datetime.now(timezone.utc).isoformat()
            self.store.update_workflow_execution(execution)
            return
            
        try:
            for idx, task in enumerate(playbook.tasks):
                execution.current_task_index = idx
                task_name = task.get("name", f"Task_{idx}")
                task_type = task.get("task_type", "generic")
                params = task.get("parameters", {})
                
                # Execute based on task type
                result = None
                if task_type == "enrich":
                    if self.enrichment_engine and incident.entities:
                        # Enrich the first entity
                        result = self.enrichment_engine.enrich_entity(incident.entities[0])
                        result = {"status": "SUCCESS", "enrichment_id": result.enrichment_id}
                elif task_type == "response" and self.response_engine:
                    from src.soar.models import ResponseActionType
                    act_type_str = params.get("action_type", "NOTIFY_ANALYST")
                    result = self.response_engine.execute_action(
                        action_type=ResponseActionType(act_type_str),
                        target_id=params.get("target_id", incident.incident_id),
                        executed_by="SYSTEM_PLAYBOOK",
                        additional_params=params
                    )
                    result = {"status": result.status, "action_id": result.action_id}
                elif task_type == "contain" and self.containment_engine:
                    from src.soar.models import ContainmentType
                    cont_type_str = params.get("containment_type", "API_BLOCK")
                    result = self.containment_engine.trigger_containment(
                        containment_type=ContainmentType(cont_type_str),
                        target_entity=params.get("target_entity", incident.entities[0] if incident.entities else "unknown"),
                        initiated_by="SYSTEM_PLAYBOOK",
                        duration_seconds=params.get("duration", 3600)
                    )
                    result = {"status": result.status, "containment_id": result.containment_id}
                elif task_type == "notify" and self.notification_engine:
                    success = self.notification_engine.send_notification(
                        channel=params.get("channel", "email"),
                        recipient=params.get("recipient", "security-alert@company.com"),
                        subject=params.get("subject", f"SOAR Alert: {incident.title}"),
                        message=params.get("message", incident.description)
                    )
                    result = {"status": "SUCCESS" if success else "FAILED"}
                else:
                    # Default generic action execution
                    result = {"status": "SUCCESS", "message": "Generic task executed"}

                execution.task_results[task_name] = result
                
                # Evaluate conditional routing in task parameters
                # e.g., if a condition specifies to skip if severity is not CRITICAL
                cond = task.get("conditional_routing")
                if cond:
                    if_sev = cond.get("if_severity_is")
                    if if_sev and incident.severity != if_sev:
                        execution.task_results[task_name]["message"] = "Skipped subsequent tasks due to condition"
                        break

            execution.state = WorkflowState.COMPLETED
            execution.end_time = datetime.now(timezone.utc).isoformat()
            self.store.update_workflow_execution(execution)
            
            self.audit_logger.log_action(
                action="WORKFLOW_COMPLETED",
                user_id="SYSTEM",
                ip_address="127.0.0.1",
                status="SUCCESS",
                details={"execution_id": execution.execution_id, "playbook_id": execution.playbook_id}
            )
        except Exception as e:
            execution.state = WorkflowState.FAILED
            execution.end_time = datetime.now(timezone.utc).isoformat()
            self.store.update_workflow_execution(execution)
            
            self.audit_logger.log_action(
                action="WORKFLOW_FAILED",
                user_id="SYSTEM",
                ip_address="127.0.0.1",
                status="FAILED",
                details={"execution_id": execution.execution_id, "error": str(e)}
            )
