"""Workflow Engine"""
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
from .models import Workflow, Case, CaseStatus, Priority, SLALevel, SLA, Escalation, Assignment

class WorkflowEngine:
    """State machine engine for case workflows"""
    
    def __init__(self) -> None:
        self.workflows: Dict[str, Workflow] = {}
        self.cases: Dict[str, Case] = {}
        self.slas: Dict[str, SLA] = {}
        self.escalations: Dict[str, Escalation] = {}
        self.assignments: Dict[str, Assignment] = {}
        self._init_default_workflows()
    
    def _init_default_workflows(self) -> None:
        """Initialize default workflows"""
        workflows = [
            Workflow(
                workflow_id="wf-standard",
                name="Standard Case Workflow",
                description="Standard workflow for case management",
                states=["NEW", "ASSIGNED", "IN_PROGRESS", "PENDING_APPROVAL", "RESOLVED", "CLOSED"],
                transitions={
                    "NEW": ["ASSIGNED"],
                    "ASSIGNED": ["IN_PROGRESS", "ESCALATED"],
                    "IN_PROGRESS": ["PENDING_APPROVAL", "RESOLVED", "ESCALATED"],
                    "PENDING_APPROVAL": ["IN_PROGRESS", "RESOLVED"],
                    "ESCALATED": ["ASSIGNED", "IN_PROGRESS"],
                    "RESOLVED": ["CLOSED", "IN_PROGRESS"],
                    "CLOSED": []
                },
                initial_state="NEW"
            ),
            Workflow(
                workflow_id="wf-incident",
                name="Incident Response Workflow",
                description="Fast-track workflow for incidents",
                states=["NEW", "INVESTIGATING", "CONTAINED", "ERADICATED", "RECOVERED", "CLOSED"],
                transitions={
                    "NEW": ["INVESTIGATING"],
                    "INVESTIGATING": ["CONTAINED", "ESCALATED"],
                    "CONTAINED": ["ERADICATED"],
                    "ERADICATED": ["RECOVERED"],
                    "RECOVERED": ["CLOSED"],
                    "ESCALATED": ["INVESTIGATING"],
                    "CLOSED": []
                },
                initial_state="NEW"
            )
        ]
        for wf in workflows:
            self.workflows[wf.workflow_id] = wf
    
    def create_workflow(
        self,
        name: str,
        description: str,
        states: List[str],
        initial_state: str
    ) -> Workflow:
        """Create a new workflow"""
        transitions = {state: [] for state in states}
        workflow = Workflow(
            workflow_id=f"wf-{uuid4().hex[:8]}",
            name=name,
            description=description,
            states=states,
            transitions=transitions,
            initial_state=initial_state
        )
        self.workflows[workflow.workflow_id] = workflow
        return workflow
    
    def add_transition(self, workflow_id: str, from_state: str, to_state: str) -> bool:
        """Add a state transition"""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return False
        if from_state in workflow.transitions and to_state in workflow.states:
            if to_state not in workflow.transitions[from_state]:
                workflow.transitions[from_state].append(to_state)
            return True
        return False
    
    def can_transition(self, workflow_id: str, from_state: str, to_state: str) -> bool:
        """Check if transition is valid"""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return False
        return to_state in workflow.transitions.get(from_state, [])
    
    def create_case(
        self,
        title: str,
        description: str,
        workflow_id: str,
        priority: str = "MEDIUM",
        assignee: Optional[str] = None
    ) -> Case:
        """Create a new case"""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow {workflow_id} not found")
        
        case = Case(
            case_id=str(uuid4())[:8],
            title=title,
            description=description,
            workflow_id=workflow_id,
            current_state=workflow.initial_state,
            status=CaseStatus.NEW,
            priority=Priority[priority],
            assignee=assignee
        )
        self.cases[case.case_id] = case
        return case
    
    def transition_case(self, case_id: str, to_state: str) -> Optional[Case]:
        """Transition a case to a new state"""
        case = self.cases.get(case_id)
        if not case:
            return None
        
        if not self.can_transition(case.workflow_id, case.current_state, to_state):
            return None
        
        case.current_state = to_state
        case.status = CaseStatus(to_state) if to_state in [s.value for s in CaseStatus] else case.status
        case.updated_at = datetime.utcnow()
        return case
    
    def get_case(self, case_id: str) -> Optional[Case]:
        """Get a case by ID"""
        return self.cases.get(case_id)
    
    def get_cases_by_assignee(self, assignee: str) -> List[Case]:
        """Get cases assigned to a user"""
        return [c for c in self.cases.values() if c.assignee == assignee]
    
    def assign_case(self, case_id: str, assignee: str, assigned_by: str) -> Optional[Assignment]:
        """Assign a case to a user"""
        case = self.cases.get(case_id)
        if not case:
            return None
        
        case.assignee = assignee
        case.updated_at = datetime.utcnow()
        
        assignment = Assignment(
            assignment_id=str(uuid4())[:8],
            case_id=case_id,
            assignee=assignee,
            assigned_by=assigned_by
        )
        self.assignments[assignment.assignment_id] = assignment
        return assignment
    
    def escalate_case(self, case_id: str, to_assignee: str, reason: str) -> Optional[Escalation]:
        """Escalate a case"""
        case = self.cases.get(case_id)
        if not case:
            return None
        
        escalation = Escalation(
            escalation_id=str(uuid4())[:8],
            case_id=case_id,
            from_assignee=case.assignee or "UNASSIGNED",
            to_assignee=to_assignee,
            reason=reason
        )
        self.escalations[escalation.escalation_id] = escalation
        
        case.escalated_to = to_assignee
        case.status = CaseStatus.ESCALATED
        case.updated_at = datetime.utcnow()
        
        return escalation
    
    def create_sla(self, case_id: str, sla_level: str) -> Optional[SLA]:
        """Create SLA for a case"""
        case = self.cases.get(case_id)
        if not case:
            return None
        
        sla_hours = {"P1": 1, "P2": 4, "P3": 24, "P4": 72}
        hours = sla_hours.get(sla_level, 24)
        
        sla = SLA(
            sla_id=str(uuid4())[:8],
            case_id=case_id,
            sla_level=SLALevel(sla_level),
            due_at=datetime.utcnow() + timedelta(hours=hours)
        )
        self.slas[sla.sla_id] = sla
        return sla
    
    def check_sla_breach(self, sla_id: str) -> bool:
        """Check and mark SLA breach"""
        sla = self.slas.get(sla_id)
        if not sla or sla.breached:
            return sla.breached if sla else False
        
        if datetime.utcnow() > sla.due_at:
            sla.breached = True
            sla.breached_at = datetime.utcnow()
            return True
        return False
    
    def get_breached_slas(self) -> List[SLA]:
        """Get all breached SLAs"""
        for sla in self.slas.values():
            self.check_sla_breach(sla.sla_id)
        return [s for s in self.slas.values() if s.breached]
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get workflow dashboard"""
        status_counts: Dict[str, int] = {}
        priority_counts: Dict[str, int] = {}
        
        for case in self.cases.values():
            status_counts[case.status.value] = status_counts.get(case.status.value, 0) + 1
            priority_counts[case.priority.name] = priority_counts.get(case.priority.name, 0) + 1
        
        return {
            "total_cases": len(self.cases),
            "total_workflows": len(self.workflows),
            "total_slas": len(self.slas),
            "breached_slas": len(self.get_breached_slas()),
            "cases_by_status": status_counts,
            "cases_by_priority": priority_counts
        }


from uuid import uuid4