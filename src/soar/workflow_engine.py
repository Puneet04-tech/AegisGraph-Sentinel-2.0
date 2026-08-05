import logging
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from src.soar.models import WorkflowExecution, WorkflowState, Playbook, ActionStatus
from src.soar.store import SOARStore
from src.soar.audit import SOARAuditLogger

logger = logging.getLogger("aegis.soar.workflow_engine")


# Task-level status constants for explicit tracking
TASK_PENDING = "PENDING"
TASK_RUNNING = "RUNNING"
TASK_SUCCESS = "SUCCESS"
TASK_FAILED = "FAILED"
TASK_SKIPPED = "SKIPPED"
TASK_ROLLED_BACK = "ROLLED_BACK"


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

        # Track reversible containment actions for rollback on failure
        containment_stack: List[str] = []

        try:
            for idx, task in enumerate(playbook.tasks):
                execution.current_task_index = idx
                task_name = task.get("name", f"Task_{idx}")
                task_type = task.get("task_type", "generic")
                params = task.get("parameters", {})

                # Evaluate conditional routing BEFORE execution
                cond = task.get("conditional_routing")
                if cond:
                    if_sev = cond.get("if_severity_is")
                    if if_sev and incident.severity != if_sev:
                        execution.task_results[task_name] = {
                            "status": TASK_SKIPPED,
                            "message": "Condition not met: severity mismatch",
                        }
                        # Mark remaining tasks as SKIPPED
                        for remaining_idx in range(idx + 1, len(playbook.tasks)):
                            remaining_name = playbook.tasks[remaining_idx].get("name", f"Task_{remaining_idx}")
                            execution.task_results[remaining_name] = {
                                "status": TASK_SKIPPED,
                                "message": "Skipped due to prior conditional routing",
                            }
                        break

                # Mark task as running
                execution.task_results[task_name] = {"status": TASK_RUNNING}

                # Execute based on task type
                result = None
                if task_type == "enrich":
                    if self.enrichment_engine and incident.entities:
                        result = self.enrichment_engine.enrich_entity(incident.entities[0])
                        result = {"status": TASK_SUCCESS, "enrichment_id": result.enrichment_id}
                    else:
                        result = {"status": TASK_SUCCESS, "message": "No enrichment engine or entities"}
                elif task_type == "response" and self.response_engine:
                    from src.soar.models import ResponseActionType
                    act_type_str = params.get("action_type", "NOTIFY_ANALYST")
                    resp = self.response_engine.execute_action(
                        action_type=ResponseActionType(act_type_str),
                        target_id=params.get("target_id", incident.incident_id),
                        executed_by="SYSTEM_PLAYBOOK",
                        additional_params=params
                    )
                    result = {"status": TASK_SUCCESS, "action_id": resp.action_id}
                elif task_type == "contain" and self.containment_engine:
                    from src.soar.models import ContainmentType
                    cont_type_str = params.get("containment_type", "API_BLOCK")
                    cont = self.containment_engine.trigger_containment(
                        containment_type=ContainmentType(cont_type_str),
                        target_entity=params.get("target_entity", incident.entities[0] if incident.entities else "unknown"),
                        initiated_by="SYSTEM_PLAYBOOK",
                        duration_seconds=params.get("duration", 3600)
                    )
                    containment_stack.append(cont.containment_id)
                    result = {"status": TASK_SUCCESS, "containment_id": cont.containment_id}
                elif task_type == "notify" and self.notification_engine:
                    success = self.notification_engine.send_notification(
                        channel=params.get("channel", "email"),
                        recipient=params.get("recipient", "security-alert@company.com"),
                        subject=params.get("subject", f"SOAR Alert: {incident.title}"),
                        message=params.get("message", incident.description)
                    )
                    result = {"status": TASK_SUCCESS if success else TASK_FAILED}
                else:
                    result = {"status": TASK_SUCCESS, "message": "Generic task executed"}

                execution.task_results[task_name] = result

                if result.get("status") == TASK_FAILED:
                    # A task reported failure without raising — roll back and
                    # fail the workflow instead of letting it end COMPLETED.
                    self._rollback_containments(containment_stack, execution)

                    execution.state = WorkflowState.FAILED
                    execution.end_time = datetime.now(timezone.utc).isoformat()
                    self.store.update_workflow_execution(execution)

                    self.audit_logger.log_action(
                        action="WORKFLOW_FAILED",
                        user_id="SYSTEM",
                        ip_address="127.0.0.1",
                        status="FAILED",
                        details={
                            "execution_id": execution.execution_id,
                            "failed_task": task_name,
                            "error": result.get("error") or result.get("message") or f"Task failed: {task_name}",
                        }
                    )
                    return

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
            # Mark current task as failed
            task_name = playbook.tasks[execution.current_task_index].get("name", f"Task_{execution.current_task_index}")
            execution.task_results[task_name] = {
                "status": TASK_FAILED,
                "error": str(e),
            }

            # Rollback containment actions in reverse order
            self._rollback_containments(containment_stack, execution)

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

    def _rollback_containments(self, containment_stack: List[str], execution: WorkflowExecution) -> None:
        """Release containment actions in reverse order (compensation/rollback)."""
        if not self.containment_engine or not containment_stack:
            return

        for containment_id in reversed(containment_stack):
            try:
                self.containment_engine.release_containment(containment_id, released_by="SYSTEM_ROLLBACK")
                logger.info(f"Rolled back containment {containment_id}")
                self.audit_logger.log_action(
                    action="WORKFLOW_ROLLBACK_CONTAINMENT",
                    user_id="SYSTEM",
                    ip_address="127.0.0.1",
                    status="SUCCESS",
                    details={"containment_id": containment_id, "execution_id": execution.execution_id}
                )
            except Exception as rollback_err:
                logger.error(f"Failed to rollback containment {containment_id}: {rollback_err}")
                self.audit_logger.log_action(
                    action="WORKFLOW_ROLLBACK_CONTAINMENT",
                    user_id="SYSTEM",
                    ip_address="127.0.0.1",
                    status="FAILED",
                    details={"containment_id": containment_id, "error": str(rollback_err)}
                )
