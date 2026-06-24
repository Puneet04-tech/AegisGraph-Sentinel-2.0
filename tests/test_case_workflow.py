"""Tests for Case Workflow Module"""
import pytest
from src.case_workflow import CaseWorkflowService, CaseStatus

def test_service_init():
    """Test service initialization"""
    service = CaseWorkflowService()
    assert service is not None
    assert len(service.engine.workflows) >= 2

def test_create_workflow():
    """Test creating a workflow"""
    service = CaseWorkflowService()
    workflow = service.create_workflow(
        name="Test Workflow",
        description="Test workflow",
        states=["A", "B", "C"],
        initial_state="A"
    )
    assert workflow is not None
    assert workflow["name"] == "Test Workflow"
    assert len(workflow["states"]) == 3

def test_get_workflow():
    """Test getting a workflow"""
    service = CaseWorkflowService()
    created = service.create_workflow("Get Test", "Desc", ["X", "Y"], "X")
    retrieved = service.get_workflow(created["workflow_id"])
    assert retrieved is not None
    assert retrieved["name"] == "Get Test"

def test_add_transition():
    """Test adding a transition"""
    service = CaseWorkflowService()
    result = service.add_transition("wf-standard", "NEW", "ASSIGNED")
    assert result is True

def test_create_case():
    """Test creating a case"""
    service = CaseWorkflowService()
    case = service.create_case(
        title="Test Case",
        description="Test description",
        priority="HIGH"
    )
    assert case is not None
    assert case["title"] == "Test Case"
    assert case["priority"] == "HIGH"

def test_get_case():
    """Test getting a case"""
    service = CaseWorkflowService()
    created = service.create_case("Get Test", "Desc")
    retrieved = service.get_case(created["case_id"])
    assert retrieved is not None
    assert retrieved["title"] == "Get Test"

def test_transition_case():
    """Test transitioning a case"""
    service = CaseWorkflowService()
    case = service.create_case("Transition Test", "Desc")
    transitioned = service.transition_case(case["case_id"], "ASSIGNED")
    assert transitioned is not None

def test_assign_case():
    """Test assigning a case"""
    service = CaseWorkflowService()
    case = service.create_case("Assign Test", "Desc")
    assignment = service.assign_case(
        case["case_id"],
        "analyst@example.com",
        "manager@example.com"
    )
    assert assignment is not None
    assert assignment["assignee"] == "analyst@example.com"

def test_escalate_case():
    """Test escalating a case"""
    service = CaseWorkflowService()
    case = service.create_case("Escalate Test", "Desc")
    escalation = service.escalate_case(
        case["case_id"],
        "senior@example.com",
        "Priority escalation"
    )
    assert escalation is not None
    assert escalation["reason"] == "Priority escalation"

def test_get_sla_status():
    """Test getting SLA status"""
    service = CaseWorkflowService()
    case = service.create_case("SLA Test", "Desc", priority="CRITICAL")
    sla = service.get_sla_status(case["case_id"])
    assert sla is not None

def test_get_breached_slas():
    """Test getting breached SLAs"""
    service = CaseWorkflowService()
    breached = service.get_breached_slas()
    assert isinstance(breached, list)

def test_get_cases_by_assignee():
    """Test filtering by assignee"""
    service = CaseWorkflowService()
    service.create_case("Assignee Test 1", "Desc", assignee="user@example.com")
    service.create_case("Assignee Test 2", "Desc", assignee="user@example.com")
    cases = service.get_cases_by_assignee("user@example.com")
    assert len(cases) >= 2

def test_get_dashboard():
    """Test dashboard data"""
    service = CaseWorkflowService()
    service.create_case("Dashboard Test", "Desc")
    dashboard = service.get_dashboard()
    assert dashboard is not None
    assert "total_cases" in dashboard
    assert "cases_by_status" in dashboard