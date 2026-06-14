"""
Multi-Agent Orchestration Engine
AegisGraph Sentinel Enterprise
Coordinates multiple AI agents for complex investigations
"""

import asyncio
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
import logging

from src.agents.base import (
    BaseAgent,
    AgentType,
    AgentTask,
    AgentStatus,
    AgentMessage,
    TaskPriority,
)

logger = logging.getLogger(__name__)


class OrchestrationStrategy(str, Enum):
    """Orchestration strategies"""
    SEQUENTIAL = "sequential"  # Execute agents one after another
    PARALLEL = "parallel"  # Execute agents in parallel
    HYBRID = "hybrid"  # Mix of sequential and parallel
    CASCADE = "cascade"  # Output of one feeds into next


@dataclass
class WorkflowStep:
    """Workflow step definition"""
    step_id: str
    agent_type: AgentType
    input_mapping: Dict[str, str]  # Maps previous step outputs to this step's inputs
    conditions: Optional[Dict[str, Any]] = None
    on_failure: str = "continue"  # continue, stop, fallback
    timeout: int = 300  # 5 minutes default


@dataclass
class Workflow:
    """Multi-agent workflow definition"""
    workflow_id: str
    name: str
    description: str
    steps: List[WorkflowStep]
    strategy: OrchestrationStrategy = OrchestrationStrategy.SEQUENTIAL
    max_parallel: int = 3
    retry_policy: Dict[str, Any] = field(default_factory=lambda: {
        "max_retries": 3,
        "backoff_multiplier": 2,
        "initial_delay": 1,
    })
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class WorkflowExecution:
    """Workflow execution state"""
    execution_id: str
    workflow_id: str
    status: AgentStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    current_step: int = 0
    step_results: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    output: Optional[Dict[str, Any]] = None


class AgentRegistry:
    """Registry for available agents"""

    def __init__(self):
        self.agents: Dict[AgentType, BaseAgent] = {}
        self.agent_factories: Dict[AgentType, Callable] = {}

    def register(self, agent_type: AgentType, agent: BaseAgent):
        """Register an agent instance"""
        self.agents[agent_type] = agent

    def register_factory(self, agent_type: AgentType, factory: Callable):
        """Register an agent factory"""
        self.agent_factories[agent_type] = factory

    def get(self, agent_type: AgentType) -> Optional[BaseAgent]:
        """Get agent by type"""
        return self.agents.get(agent_type)

    def create(self, agent_type: AgentType, config: Dict[str, Any]) -> BaseAgent:
        """Create new agent instance"""
        if agent_type in self.agent_factories:
            return self.agent_factories[agent_type](config)
        raise ValueError(f"No factory registered for agent type: {agent_type}")

    def list_types(self) -> List[AgentType]:
        """List available agent types"""
        return list(self.agents.keys())


class OrchestrationEngine:
    """Multi-agent orchestration engine"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.registry = AgentRegistry()
        self.active_workflows: Dict[str, WorkflowExecution] = {}
        
        # Default timeout for agent execution
        self.default_timeout = config.get("default_timeout", 300)

    def register_agent(self, agent_type: AgentType, agent: BaseAgent):
        """Register an agent with the engine"""
        self.registry.register(agent_type, agent)

    async def execute_workflow(
        self,
        workflow: Workflow,
        initial_input: Dict[str, Any],
        callback: Optional[Callable] = None,
    ) -> WorkflowExecution:
        """Execute a multi-agent workflow"""
        execution_id = f"exec_{workflow.workflow_id}_{datetime.utcnow().timestamp()}"
        
        execution = WorkflowExecution(
            execution_id=execution_id,
            workflow_id=workflow.workflow_id,
            status=AgentStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        
        self.active_workflows[execution_id] = execution
        
        try:
            if workflow.strategy == OrchestrationStrategy.SEQUENTIAL:
                await self._execute_sequential(workflow, execution, initial_input, callback)
            elif workflow.strategy == OrchestrationStrategy.PARALLEL:
                await self._execute_parallel(workflow, execution, initial_input, callback)
            elif workflow.strategy == OrchestrationStrategy.HYBRID:
                await self._execute_hybrid(workflow, execution, initial_input, callback)
            elif workflow.strategy == OrchestrationStrategy.CASCADE:
                await self._execute_cascade(workflow, execution, initial_input, callback)
            
            execution.status = AgentStatus.COMPLETED
            execution.completed_at = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Workflow {workflow.workflow_id} failed: {e}")
            execution.status = AgentStatus.FAILED
            execution.errors.append({
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            })
            execution.completed_at = datetime.utcnow()
        
        return execution

    async def _execute_sequential(
        self,
        workflow: Workflow,
        execution: WorkflowExecution,
        initial_input: Dict[str, Any],
        callback: Optional[Callable],
    ):
        """Execute workflow steps sequentially"""
        current_output = initial_input
        
        for i, step in enumerate(workflow.steps):
            execution.current_step = i
            
            # Check conditions
            if step.conditions and not self._evaluate_conditions(step.conditions, current_output):
                logger.info(f"Step {step.step_id} skipped due to conditions")
                continue
            
            # Execute step
            result = await self._execute_step(step, current_output, execution, callback)
            
            if result:
                execution.step_results.append({
                    "step_id": step.step_id,
                    "result": result,
                    "timestamp": datetime.utcnow().isoformat(),
                })
                
                # Map outputs for next step
                current_output = self._map_outputs(step.input_mapping, current_output, result)
            elif step.on_failure == "stop":
                raise Exception(f"Step {step.step_id} failed and stop-on-failure is set")
        
        execution.output = current_output

    async def _execute_parallel(
        self,
        workflow: Workflow,
        execution: WorkflowExecution,
        initial_input: Dict[str, Any],
        callback: Optional[Callable],
    ):
        """Execute workflow steps in parallel"""
        tasks = []
        
        for step in workflow.steps:
            if step.conditions and not self._evaluate_conditions(step.conditions, initial_input):
                continue
            
            task = self._execute_step(step, initial_input, execution, callback)
            tasks.append((step, task))
        
        # Execute in batches
        results = []
        for i in range(0, len(tasks), workflow.max_parallel):
            batch = tasks[i:i + workflow.max_parallel]
            batch_results = await asyncio.gather(*[t[1] for t in batch], return_exceptions=True)
            
            for (step, _), result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    if step.on_failure == "stop":
                        raise result
                    execution.errors.append({
                        "step_id": step.step_id,
                        "error": str(result),
                    })
                else:
                    results.append(result)
                    execution.step_results.append({
                        "step_id": step.step_id,
                        "result": result,
                        "timestamp": datetime.utcnow().isoformat(),
                    })
        
        execution.output = {"results": results}

    async def _execute_hybrid(
        self,
        workflow: Workflow,
        execution: WorkflowExecution,
        initial_input: Dict[str, Any],
        callback: Optional[Callable],
    ):
        """Execute workflow with hybrid strategy"""
        # Group steps by dependencies
        groups = self._group_steps_by_dependencies(workflow.steps)
        
        for group in groups:
            if len(group) == 1:
                # Sequential execution for single step
                step = group[0]
                result = await self._execute_step(step, initial_input, execution, callback)
                initial_input = self._map_outputs(step.input_mapping, initial_input, result)
            else:
                # Parallel execution for dependent steps
                tasks = []
                for step in group:
                    task = self._execute_step(step, initial_input, execution, callback)
                    tasks.append((step, task))
                
                batch_results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)
                
                for (step, _), result in zip(tasks, batch_results):
                    if not isinstance(result, Exception):
                        initial_input = self._map_outputs(step.input_mapping, initial_input, result)
                        execution.step_results.append({
                            "step_id": step.step_id,
                            "result": result,
                        })
        
        execution.output = initial_input

    async def _execute_cascade(
        self,
        workflow: Workflow,
        execution: WorkflowExecution,
        initial_input: Dict[str, Any],
        callback: Optional[Callable],
    ):
        """Execute workflow in cascade mode (output feeds next)"""
        current_input = initial_input
        
        for i, step in enumerate(workflow.steps):
            execution.current_step = i
            
            # Only pass previous step's output
            if i > 0 and execution.step_results:
                last_result = execution.step_results[-1]["result"]
                current_input = {**current_input, "cascade_output": last_result}
            
            result = await self._execute_step(step, current_input, execution, callback)
            
            if result:
                execution.step_results.append({
                    "step_id": step.step_id,
                    "result": result,
                    "timestamp": datetime.utcnow().isoformat(),
                })
        
        execution.output = execution.step_results[-1]["result"] if execution.step_results else {}

    async def _execute_step(
        self,
        step: WorkflowStep,
        input_data: Dict[str, Any],
        execution: WorkflowExecution,
        callback: Optional[Callable],
    ) -> Optional[Dict[str, Any]]:
        """Execute a single workflow step"""
        agent = self.registry.get(step.agent_type)
        
        if not agent:
            raise ValueError(f"Agent not found for type: {step.agent_type}")
        
        # Create task
        task = AgentTask(
            id=f"task_{step.step_id}_{datetime.utcnow().timestamp()}",
            agent_type=step.agent_type,
            priority=TaskPriority.NORMAL,
            input_data=input_data,
            created_at=datetime.utcnow(),
        )
        
        # Execute with timeout
        try:
            result = await asyncio.wait_for(
                agent.execute(task),
                timeout=step.timeout or self.default_timeout
            )
            
            if callback:
                await callback(step.step_id, result)
            
            return result
            
        except asyncio.TimeoutError:
            logger.warning(f"Step {step.step_id} timed out after {step.timeout}s")
            if step.on_failure == "stop":
                raise Exception(f"Step {step.step_id} timed out")
            return None
        except Exception as e:
            logger.error(f"Step {step.step_id} failed: {e}")
            if step.on_failure == "stop":
                raise
            return None

    def _evaluate_conditions(
        self,
        conditions: Dict[str, Any],
        context: Dict[str, Any],
    ) -> bool:
        """Evaluate step conditions"""
        for key, expected in conditions.items():
            if key not in context:
                return False
            if context[key] != expected:
                return False
        return True

    def _map_outputs(
        self,
        input_mapping: Dict[str, str],
        current_output: Dict[str, Any],
        new_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Map step outputs to next step inputs"""
        mapped = current_output.copy()
        
        for target, source in input_mapping.items():
            # Source can be in new_result or current_output
            if source in new_result:
                mapped[target] = new_result[source]
            elif source in current_output:
                mapped[target] = current_output[source]
        
        # Add new result with step-specific prefix
        mapped[f"step_{len(current_output.get('steps', []))}_output"] = new_result
        
        return mapped

    def _group_steps_by_dependencies(
        self,
        steps: List[WorkflowStep],
    ) -> List[List[WorkflowStep]]:
        """Group steps by dependencies for hybrid execution"""
        groups = []
        independent = []
        dependent = []
        
        for step in steps:
            if step.input_mapping:
                dependent.append(step)
            else:
                independent.append(step)
        
        if independent:
            groups.append(independent)
        if dependent:
            groups.append(dependent)
        
        return groups

    def get_workflow_status(self, execution_id: str) -> Optional[WorkflowExecution]:
        """Get workflow execution status"""
        return self.active_workflows.get(execution_id)

    def cancel_workflow(self, execution_id: str) -> bool:
        """Cancel a running workflow"""
        execution = self.active_workflows.get(execution_id)
        if execution and execution.status == AgentStatus.RUNNING:
            execution.status = AgentStatus.FAILED
            execution.completed_at = datetime.utcnow()
            execution.errors.append({
                "error": "Cancelled by user",
                "timestamp": datetime.utcnow().isoformat(),
            })
            return True
        return False


# Pre-built workflows
def create_fraud_investigation_workflow() -> Workflow:
    """Create standard fraud investigation workflow"""
    return Workflow(
        workflow_id="fraud_investigation_v1",
        name="Fraud Investigation",
        description="Multi-agent fraud investigation with evidence gathering",
        strategy=OrchestrationStrategy.SEQUENTIAL,
        steps=[
            WorkflowStep(
                step_id="collect_evidence",
                agent_type=AgentType.INVESTIGATION,
                input_mapping={},
                timeout=120,
            ),
            WorkflowStep(
                step_id="threat_analysis",
                agent_type=AgentType.THREAT_INTELLIGENCE,
                input_mapping={"evidence": "collect_evidence_output"},
                timeout=180,
            ),
            WorkflowStep(
                step_id="compliance_check",
                agent_type=AgentType.COMPLIANCE,
                input_mapping={"context": "threat_analysis_output"},
                timeout=60,
            ),
            WorkflowStep(
                step_id="forensic_analysis",
                agent_type=AgentType.FORENSICS,
                input_mapping={"evidence": "collect_evidence_output"},
                timeout=240,
            ),
            WorkflowStep(
                step_id="generate_report",
                agent_type=AgentType.REPORTING,
                input_mapping={
                    "investigation": "collect_evidence_output",
                    "threats": "threat_analysis_output",
                    "compliance": "compliance_check_output",
                    "forensics": "forensic_analysis_output",
                },
                timeout=60,
            ),
        ],
    )


def create_threat_hunting_workflow() -> Workflow:
    """Create threat hunting workflow"""
    return Workflow(
        workflow_id="threat_hunting_v1",
        name="Threat Hunting",
        description="Automated threat hunting across multiple data sources",
        strategy=OrchestrationStrategy.PARALLEL,
        max_parallel=3,
        steps=[
            WorkflowStep(
                step_id="network_analysis",
                agent_type=AgentType.THREAT_INTELLIGENCE,
                input_mapping={},
                timeout=300,
            ),
            WorkflowStep(
                step_id="endpoint_analysis",
                agent_type=AgentType.FORENSICS,
                input_mapping={},
                timeout=300,
            ),
            WorkflowStep(
                step_id="user_behavior",
                agent_type=AgentType.INVESTIGATION,
                input_mapping={},
                timeout=300,
            ),
            WorkflowStep(
                step_id="correlate_findings",
                agent_type=AgentType.REPORTING,
                input_mapping={
                    "network": "network_analysis_output",
                    "endpoint": "endpoint_analysis_output",
                    "behavior": "user_behavior_output",
                },
                timeout=120,
            ),
        ],
    )


# Initialize orchestration engine
orchestration_engine = OrchestrationEngine({
    "default_timeout": 300,
    "max_retries": 3,
})