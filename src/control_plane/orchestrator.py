"""Control Plane Orchestrator"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime
from .models import SecurityControl, ControlExecution, Workflow, ModuleType, PolicyType, ControlStatus

class ControlOrchestrator:
    """Orchestrates security controls across all modules"""
    
    def __init__(self) -> None:
        self.controls: Dict[str, SecurityControl] = {}
        self.executions: Dict[str, ControlExecution] = {}
        self.workflows: Dict[str, Workflow] = {}
        self._init_default_controls()
    
    def _init_default_controls(self) -> None:
        """Initialize default security controls"""
        default_controls = [
            SecurityControl(
                control_id="ctrl-001",
                name="Fraud Detection Control",
                description="Enable real-time fraud detection",
                module_type=ModuleType.FRAUD,
                policy_type=PolicyType.SECURITY,
                priority=1
            ),
            SecurityControl(
                control_id="ctrl-002",
                name="CTI Feed Control",
                description="Manage threat intelligence feeds",
                module_type=ModuleType.CTI,
                policy_type=PolicyType.SECURITY,
                priority=2
            ),
            SecurityControl(
                control_id="ctrl-003",
                name="Governance Policy Control",
                description="Enforce governance policies",
                module_type=ModuleType.GOVERNANCE,
                policy_type=PolicyType.ACCESS,
                priority=1
            ),
            SecurityControl(
                control_id="ctrl-004",
                name="Risk Assessment Control",
                description="Continuous risk assessment",
                module_type=ModuleType.RISK,
                policy_type=PolicyType.OPERATIONAL,
                priority=2
            )
        ]
        for ctrl in default_controls:
            self.controls[ctrl.control_id] = ctrl
    
    def add_control(self, control: SecurityControl) -> str:
        """Add a security control"""
        self.controls[control.control_id] = control
        return control.control_id
    
    def get_control(self, control_id: str) -> Optional[SecurityControl]:
        """Get a control by ID"""
        return self.controls.get(control_id)
    
    def get_controls_by_module(self, module_type: ModuleType) -> List[SecurityControl]:
        """Get controls for a specific module"""
        return [c for c in self.controls.values() if c.module_type == module_type]
    
    def execute_control(self, control_id: str) -> ControlExecution:
        """Execute a security control"""
        control = self.controls.get(control_id)
        if not control:
            execution = ControlExecution(
                execution_id=str(uuid4()),
                control_id=control_id,
                status=ControlStatus.FAILED,
                module_type=ModuleType.FRAUD,
                error="Control not found"
            )
            self.executions[execution.execution_id] = execution
            return execution
        
        execution = ControlExecution(
            execution_id=str(uuid4()),
            control_id=control_id,
            status=ControlStatus.RUNNING,
            module_type=control.module_type
        )
        self.executions[execution.execution_id] = execution
        
        # Simulate control execution
        execution.status = ControlStatus.COMPLETED
        execution.result = {"success": True, "control": control.name}
        execution.completed_at = datetime.utcnow()
        
        return execution
    
    def create_workflow(
        self,
        name: str,
        description: str,
        control_ids: List[str],
        modules: List[str]
    ) -> Workflow:
        """Create a global workflow"""
        steps = []
        for i, ctrl_id in enumerate(control_ids):
            control = self.controls.get(ctrl_id)
            steps.append({
                "step": i + 1,
                "control_id": ctrl_id,
                "control_name": control.name if control else "Unknown",
                "timeout": 60
            })
        
        workflow = Workflow(
            workflow_id=str(uuid4()),
            name=name,
            description=description,
            steps=steps,
            modules_involved=[ModuleType(m) for m in modules]
        )
        self.workflows[workflow.workflow_id] = workflow
        return workflow
    
    def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """Get a workflow by ID"""
        return self.workflows.get(workflow_id)
    
    def get_all_workflows(self) -> List[Workflow]:
        """Get all workflows"""
        return list(self.workflows.values())
    
    def get_execution_stats(self) -> Dict[str, Any]:
        """Get execution statistics"""
        status_counts: Dict[str, int] = {}
        for exec in self.executions.values():
            status_counts[exec.status.value] = status_counts.get(exec.status.value, 0) + 1
        
        return {
            "total_controls": len(self.controls),
            "total_executions": len(self.executions),
            "total_workflows": len(self.workflows),
            "execution_by_status": status_counts
        }