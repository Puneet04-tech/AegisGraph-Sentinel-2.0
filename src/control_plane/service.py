"""Control Plane Service"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from .models import SecurityControl, ControlExecution, Workflow, ModuleType, PolicyType
from .orchestrator import ControlOrchestrator

class ControlPlaneService:
    """Main service for Security Control Plane"""
    
    def __init__(self) -> None:
        self.orchestrator = ControlOrchestrator()
    
    def create_control(
        self,
        name: str,
        description: str,
        module_type: str,
        policy_type: str,
        priority: int = 1
    ) -> Dict[str, Any]:
        """Create a new security control"""
        control = SecurityControl(
            control_id=f"ctrl-{uuid4().hex[:8]}",
            name=name,
            description=description,
            module_type=ModuleType(module_type),
            policy_type=PolicyType(policy_type),
            priority=priority
        )
        self.orchestrator.add_control(control)
        return control.to_dict()
    
    def get_control(self, control_id: str) -> Optional[Dict[str, Any]]:
        """Get a control by ID"""
        control = self.orchestrator.get_control(control_id)
        return control.to_dict() if control else None
    
    def get_all_controls(self) -> List[Dict[str, Any]]:
        """Get all controls"""
        return [c.to_dict() for c in self.orchestrator.controls.values()]
    
    def get_controls_by_module(self, module_type: str) -> List[Dict[str, Any]]:
        """Get controls for a module"""
        controls = self.orchestrator.get_controls_by_module(ModuleType(module_type))
        return [c.to_dict() for c in controls]
    
    def execute_control(self, control_id: str) -> Dict[str, Any]:
        """Execute a control"""
        execution = self.orchestrator.execute_control(control_id)
        return execution.to_dict()
    
    def create_workflow(
        self,
        name: str,
        description: str,
        control_ids: List[str],
        modules: List[str]
    ) -> Dict[str, Any]:
        """Create a workflow"""
        import uuid
        workflow = self.orchestrator.create_workflow(name, description, control_ids, modules)
        return workflow.to_dict()
    
    def get_workflow(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get a workflow"""
        workflow = self.orchestrator.get_workflow(workflow_id)
        return workflow.to_dict() if workflow else None
    
    def get_all_workflows(self) -> List[Dict[str, Any]]:
        """Get all workflows"""
        return [w.to_dict() for w in self.orchestrator.get_all_workflows()]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get control plane statistics"""
        return self.orchestrator.get_execution_stats()
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get dashboard data"""
        stats = self.get_stats()
        controls = self.get_all_controls()
        return {
            "stats": stats,
            "controls_count": len(controls),
            "modules_managed": len(set(c["module_type"] for c in controls))
        }


# Global service instance
_control_plane_service: Optional[ControlPlaneService] = None

def get_control_plane_service() -> ControlPlaneService:
    """Get the global service instance"""
    global _control_plane_service
    if _control_plane_service is None:
        _control_plane_service = ControlPlaneService()
    return _control_plane_service