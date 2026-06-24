"""Case Workflow Service"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from .models import Workflow, Case, SLA, Escalation, Assignment, CaseStatus, Priority, SLALevel
from .workflow_engine import WorkflowEngine

class CaseWorkflowService:
    """Main service for case workflow automation"""
    
    def __init__(self) -> None:
        self.engine = WorkflowEngine()
    
    def create_workflow(
        self,
        name: str,
        description: str,
        states: List[str],
        initial_state: str
    ) -> Dict[str, Any]:
        """Create a new workflow"""
        workflow = self.engine.create_workflow(name, description, states, initial_state)
        return workflow.to_dict()
    
    def get_workflow(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get a workflow"""
        workflow = self.engine.workflows.get(workflow_id)
        return workflow.to_dict() if workflow else None
    
    def get_all_workflows(self) -> List[Dict[str, Any]]:
        """Get all workflows"""
        return [w.to_dict() for w in self.engine.workflows.values()]
    
    def add_transition(
        self,
        workflow_id: str,
        from_state: str,
        to_state: str
    ) -> bool:
        """Add a state transition"""
        return self.engine.add_transition(workflow_id, from_state, to_state)
    
    def create_case(
        self,
        title: str,
        description: str,
        workflow_id: str = "wf-standard",
        priority: str = "MEDIUM",
        assignee: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new case"""
        case = self.engine.create_case(title, description, workflow_id, priority, assignee)
        # Create SLA
        self.engine.create_sla(case.case_id, f"P{list(Priority).index(Priority[priority]) + 1}")
        return case.to_dict()
    
    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get a case"""
        case = self.engine.get_case(case_id)
        return case.to_dict() if case else None
    
    def get_all_cases(self) -> List[Dict[str, Any]]:
        """Get all cases"""
        return [c.to_dict() for c in self.engine.cases.values()]
    
    def transition_case(self, case_id: str, to_state: str) -> Optional[Dict[str, Any]]:
        """Transition a case"""
        case = self.engine.transition_case(case_id, to_state)
        return case.to_dict() if case else None
    
    def assign_case(
        self,
        case_id: str,
        assignee: str,
        assigned_by: str
    ) -> Optional[Dict[str, Any]]:
        """Assign a case"""
        assignment = self.engine.assign_case(case_id, assignee, assigned_by)
        return assignment.to_dict() if assignment else None
    
    def escalate_case(
        self,
        case_id: str,
        to_assignee: str,
        reason: str
    ) -> Optional[Dict[str, Any]]:
        """Escalate a case"""
        escalation = self.engine.escalate_case(case_id, to_assignee, reason)
        return escalation.to_dict() if escalation else None
    
    def get_sla_status(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get SLA status for a case"""
        for sla in self.engine.slas.values():
            if sla.case_id == case_id:
                self.engine.check_sla_breach(sla.sla_id)
                return sla.to_dict()
        return None
    
    def get_breached_slas(self) -> List[Dict[str, Any]]:
        """Get all breached SLAs"""
        return [s.to_dict() for s in self.engine.get_breached_slas()]
    
    def get_cases_by_assignee(self, assignee: str) -> List[Dict[str, Any]]:
        """Get cases assigned to a user"""
        return [c.to_dict() for c in self.engine.get_cases_by_assignee(assignee)]
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get dashboard data"""
        return self.engine.get_dashboard()


# Global service instance
_case_workflow_service: Optional[CaseWorkflowService] = None

def get_case_workflow_service() -> CaseWorkflowService:
    """Get the global service instance"""
    global _case_workflow_service
    if _case_workflow_service is None:
        _case_workflow_service = CaseWorkflowService()
    return _case_workflow_service