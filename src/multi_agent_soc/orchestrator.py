"""
Agent Orchestrator.

Orchestrates multi-agent workflows, manages task dependencies, and coordinates agent collaboration.
"""

import random
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timezone, timedelta
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import (
    AgentTask,
    AgentType,
    TaskPriority,
    TaskStatus,
    OrchestrationPlan,
    AgentMessage,
)
from .store import SOCStore, get_soc_store

logger = logging.getLogger(__name__)
__all__ = ['AgentOrchestrator', 'get_orchestrator', 'WorkflowValidationError']



class WorkflowValidationError(ValueError):
    """Raised when a workflow task definition fails validation.

    Carries structured context so the API layer can return a precise 400
    instead of surfacing an uncaught ``ValueError`` as a 500.
    """

    def __init__(
        self,
        message: str,
        task_index: int,
        field: str,
        invalid_value: Any,
        valid_values: List[str],
    ):
        super().__init__(message)
        self.task_index = task_index
        self.field = field
        self.invalid_value = invalid_value
        self.valid_values = valid_values


class AgentOrchestrator:
    """Orchestrates multi-agent fraud investigation workflows.
    
    Capabilities:
        - Task orchestration and scheduling
        - Agent collaboration management
        - Parallel task execution
        - Workflow automation
        - Result aggregation
    """
    
    def __init__(self, store: Optional[SOCStore] = None):
        """Initialize the orchestrator.
        
        Args:
            store: Optional SOC store
        """
        self._store = store or get_soc_store()
        
        # Agent registry
        self._agents: Dict[AgentType, Callable] = {}
        self._register_default_agents()
    
    def _register_default_agents(self):
        """Register default SOC agents."""
        from .investigation_agent import get_investigation_agent
        from .threat_intelligence_agent import get_threat_intelligence_agent
        from .forensics_agent import get_forensics_agent
        from .fraud_ring_agent import get_fraud_ring_agent
        from .reporting_agent import get_reporting_agent
        
        self._agents[AgentType.INVESTIGATION] = get_investigation_agent
        self._agents[AgentType.THREAT_INTELLIGENCE] = get_threat_intelligence_agent
        self._agents[AgentType.FORENSICS] = get_forensics_agent
        self._agents[AgentType.FRAUD_RING] = get_fraud_ring_agent
        self._agents[AgentType.REPORTING] = get_reporting_agent
    
    def orchestrate_investigation(
        self,
        entity_id: str,
        priority: TaskPriority = TaskPriority.HIGH,
    ) -> Dict[str, Any]:
        """Orchestrate a multi-agent investigation.
        
        Args:
            entity_id: Entity to investigate
            priority: Investigation priority
            
        Returns:
            Orchestration results
        """
        logger.info(f"Orchestrating investigation for {entity_id}")
        
        results = {}
        
        # Step 1: Investigation agent analysis
        investigation_agent = self._agents[AgentType.INVESTIGATION]()
        inv_result = investigation_agent.analyze_entity(entity_id)
        results["investigation"] = inv_result.to_dict() if hasattr(inv_result, 'to_dict') else {
            "entity_id": inv_result.entity_id,
            "risk_score": inv_result.risk_score,
            "status": inv_result.status.value,
        }
        
        # Step 2: If high risk, trigger threat intelligence
        if inv_result.risk_score >= 0.7:
            threat_agent = self._agents[AgentType.THREAT_INTELLIGENCE]()
            threat_report = threat_agent.analyze_threat(
                threat_type="high_risk_entity",
                indicators=[{"entity_id": entity_id, "risk_score": inv_result.risk_score}],
            )
            results["threat_intelligence"] = {
                "report_id": threat_report.report_id,
                "severity": threat_report.severity,
                "confidence": threat_report.confidence,
            }
        
        # Step 3: Forensics if needed
        if inv_result.risk_score >= 0.8:
            forensics_agent = self._agents[AgentType.FORENSICS]()
            forensics_result = forensics_agent.perform_forensics(
                target_entity_id=entity_id,
                analysis_type="comprehensive",
            )
            results["forensics"] = {
                "analysis_id": forensics_result.analysis_id,
                "conclusion": forensics_result.conclusion,
            }
        
        # Step 4: Fraud ring detection
        if inv_result.risk_score >= 0.6:
            ring_agent = self._agents[AgentType.FRAUD_RING]()
            ring_analysis = ring_agent.detect_ring(
                seed_entities=[entity_id],
                ring_type="connected_fraud",
            )
            results["fraud_ring"] = {
                "ring_id": ring_analysis.ring_id,
                "ring_score": ring_analysis.ring_score,
                "member_count": len(ring_analysis.member_entities),
            }
        
        # Step 5: Generate report
        reporting_agent = self._agents[AgentType.REPORTING]()
        report = reporting_agent.generate_summary_report(
            period_start=datetime.now(timezone.utc) - timedelta(hours=24),
            period_end=datetime.now(timezone.utc),
            report_type="investigation",
        )
        results["report"] = {
            "report_id": report.report_id,
            "recommendations": report.recommendations,
        }
        
        return results
    
    def create_workflow(
        self,
        workflow_name: str,
        tasks: List[Dict[str, Any]],
        parallel_threshold: int = 3,
    ) -> OrchestrationPlan:
        """Create an orchestration workflow.
        
        Args:
            workflow_name: Name of the workflow
            tasks: List of task definitions
            parallel_threshold: Tasks above this are parallelized
            
        Returns:
            OrchestrationPlan
        """
        logger.info(f"Creating workflow: {workflow_name}")
        
        plan_tasks = []
        parallel_groups = []
        current_parallel = []
        
        for task_index, task_def in enumerate(tasks):
            if not isinstance(task_def, dict):
                raise WorkflowValidationError(
                    f"Task definition at index {task_index} must be an object",
                    task_index=task_index,
                    field="task",
                    invalid_value=task_def,
                    valid_values=["object"],
                )

            agent_type_value = str(task_def.get("agent_type", "INVESTIGATION")).upper()
            if agent_type_value not in AgentType.__members__:
                raise WorkflowValidationError(
                    f"Invalid agent_type '{task_def.get('agent_type')}' for task "
                    f"{task_index}; valid values: {', '.join(AgentType.__members__)}",
                    task_index=task_index,
                    field="agent_type",
                    invalid_value=task_def.get("agent_type"),
                    valid_values=list(AgentType.__members__),
                )

            priority_value = str(task_def.get("priority", "MEDIUM")).upper()
            if priority_value not in TaskPriority.__members__:
                raise WorkflowValidationError(
                    f"Invalid priority '{task_def.get('priority')}' for task "
                    f"{task_index}; valid values: {', '.join(TaskPriority.__members__)}",
                    task_index=task_index,
                    field="priority",
                    invalid_value=task_def.get("priority"),
                    valid_values=list(TaskPriority.__members__),
                )

            task = AgentTask(
                agent_type=AgentType(agent_type_value),
                title=task_def.get("title", "Task"),
                description=task_def.get("description", ""),
                priority=TaskPriority(priority_value),
                context=task_def.get("context", {}),
            )
            plan_tasks.append(task)
            self._store.store_task(task)
            
            # Group for parallel execution
            if len(current_parallel) < parallel_threshold:
                current_parallel.append(task.task_id)
            else:
                if current_parallel:
                    parallel_groups.append(current_parallel)
                current_parallel = [task.task_id]
        
        if current_parallel:
            parallel_groups.append(current_parallel)
        
        plan = OrchestrationPlan(
            title=workflow_name,
            description=f"Orchestrated workflow: {workflow_name}",
            tasks=plan_tasks,
            parallel_groups=parallel_groups,
            estimated_duration_seconds=len(tasks) * 60,  # 1 minute per task estimate
            priority=TaskPriority.MEDIUM,
        )
        
        self._store.store_plan(plan)
        logger.info(f"Created plan {plan.plan_id} with {len(tasks)} tasks")
        
        return plan
    
    def execute_plan(self, plan_id: str) -> Dict[str, Any]:
        """Execute an orchestration plan.
        
        Args:
            plan_id: Plan to execute
            
        Returns:
            Execution results
        """
        plan = self._store.get_plan(plan_id)
        if not plan:
            return {"error": "Plan not found"}
        
        logger.info(f"Executing plan: {plan_id}")
        
        plan.status = "IN_PROGRESS"
        plan.started_at = datetime.now(timezone.utc)
        self._store.store_plan(plan)
        
        results = {"completed": [], "failed": [], "parallel": []}
        
        # Execute parallel groups; tasks within a group run concurrently.
        for group in plan.parallel_groups:
            group_results = {}
            
            def _run_task(task_id: str) -> Dict[str, Any]:
                task = self._store.get_task(task_id)
                if task:
                    return task.task_id, self._execute_task(task)
                return task_id, {"error": f"Task {task_id} not found"}
            
            with ThreadPoolExecutor(max_workers=max(1, len(group))) as pool:
                futures = {
                    pool.submit(_run_task, task_id): task_id for task_id in group
                }
                for future in as_completed(futures):
                    task_id = futures[future]
                    try:
                        _, result = future.result()
                    except Exception as exc:
                        logger.error(f"Task {task_id} failed: {exc}")
                        task = self._store.get_task(task_id)
                        if task:
                            task.status = TaskStatus.FAILED
                            task.result = {"error": str(exc)}
                            self._store.store_task(task)
                        result = {"error": str(exc)}
                    
                    group_results[task_id] = result
                    if isinstance(result, dict) and "error" in result:
                        results["failed"].append(task_id)
                    else:
                        results["completed"].append(task_id)
            
            results["parallel"].append(group_results)
        
        plan.status = "COMPLETED" if not results["failed"] else "FAILED"
        plan.completed_at = datetime.now(timezone.utc)
        self._store.store_plan(plan)
        
        return results
    
    def _execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute a single task."""
        task.status = TaskStatus.IN_PROGRESS
        task.started_at = datetime.now(timezone.utc)
        
        # Get the agent
        agent_factory = self._agents.get(task.agent_type)
        if not agent_factory:
            task.status = TaskStatus.FAILED
            return {"error": f"No agent for type {task.agent_type}"}
        
        agent = agent_factory()
        
        # Execute based on agent type
        result = {}
        if task.agent_type == AgentType.INVESTIGATION:
            entity_id = task.context.get("entity_id", task.title.split()[-1])
            inv_result = agent.analyze_entity(entity_id, task.context)
            result = {"risk_score": inv_result.risk_score}
        elif task.agent_type == AgentType.THREAT_INTELLIGENCE:
            threat_report = agent.analyze_threat(
                threat_type="orchestrated_threat",
                indicators=[],
                context=task.context,
            )
            result = {"severity": threat_report.severity}
        elif task.agent_type == AgentType.FORENSICS:
            forensics = agent.perform_forensics(
                target_entity_id=task.context.get("entity_id", "unknown"),
                analysis_type="comprehensive",
            )
            result = {"conclusion": forensics.conclusion}
        elif task.agent_type == AgentType.FRAUD_RING:
            ring = agent.detect_ring(
                seed_entities=task.context.get("seed_entities", []),
                ring_type="orchestrated_ring",
            )
            result = {"ring_score": ring.ring_score}
        elif task.agent_type == AgentType.REPORTING:
            report = agent.generate_summary_report(
                period_start=datetime.now(timezone.utc),
                period_end=datetime.now(timezone.utc),
            )
            result = {"report_id": report.report_id}
        
        task.status = TaskStatus.COMPLETED
        task.completed_at = datetime.now(timezone.utc)
        task.result = result
        
        return result
    
    def coordinate_agents(
        self,
        source_agent: AgentType,
        target_agents: List[AgentType],
        message: Dict[str, Any],
    ) -> List[AgentMessage]:
        """Coordinate message passing between agents.
        
        Args:
            source_agent: Source agent type
            target_agents: Target agent types
            message: Message content
            
        Returns:
            List of AgentMessages
        """
        messages = []
        source_id = f"{source_agent.value}_agent"
        
        for target_agent in target_agents:
            target_id = f"{target_agent.value}_agent"
            
            msg = AgentMessage(
                from_agent=source_id,
                to_agent=target_id,
                message_type=message.get("type", "task_delegation"),
                content=message.get("content", {}),
            )
            
            self._store._messages.append(msg)
            messages.append(msg)
        
        return messages
    
    def get_orchestration_status(self) -> Dict[str, Any]:
        """Get overall orchestration status."""
        stats = self._store.get_stats()
        active_plan = self._store.get_active_plan()
        
        return {
            "total_agents": stats["total_agents"],
            "active_tasks": stats["pending_tasks"],
            "completed_tasks": stats["total_tasks"] - stats["pending_tasks"],
            "active_plan": active_plan.plan_id if active_plan else None,
            "plan_status": active_plan.status if active_plan else None,
            "agent_types": [at.value for at in AgentType],
        }


# Global singleton
_orchestrator: Optional[AgentOrchestrator] = None


def get_orchestrator(store: Optional[SOCStore] = None) -> AgentOrchestrator:
    """Get or create the singleton AgentOrchestrator instance."""
    global _orchestrator
    
    if _orchestrator is None:
        _orchestrator = AgentOrchestrator(store=store)
    return _orchestrator