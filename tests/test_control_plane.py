"""Tests for Control Plane Module"""
import pytest
from src.control_plane import ControlPlaneService, ModuleType, PolicyType

def test_service_init():
    """Test service initialization"""
    service = ControlPlaneService()
    assert service is not None
    assert service.orchestrator is not None

def test_create_control():
    """Test creating a control"""
    service = ControlPlaneService()
    control = service.create_control(
        name="Test Control",
        description="Test control description",
        module_type="FRAUD",
        policy_type="SECURITY",
        priority=1
    )
    assert control is not None
    assert control["name"] == "Test Control"
    assert control["module_type"] == "FRAUD"

def test_get_control():
    """Test getting a control"""
    service = ControlPlaneService()
    created = service.create_control(
        name="Get Test",
        description="Test",
        module_type="CTI",
        policy_type="ACCESS"
    )
    retrieved = service.get_control(created["control_id"])
    assert retrieved is not None
    assert retrieved["name"] == "Get Test"

def test_get_all_controls():
    """Test getting all controls"""
    service = ControlPlaneService()
    controls = service.get_all_controls()
    assert len(controls) >= 4  # Default controls

def test_get_controls_by_module():
    """Test filtering controls by module"""
    service = ControlPlaneService()
    service.create_control(
        name="Fraud Control",
        description="Test",
        module_type="FRAUD",
        policy_type="SECURITY"
    )
    controls = service.get_controls_by_module("FRAUD")
    assert all(c["module_type"] == "FRAUD" for c in controls)

def test_execute_control():
    """Test executing a control"""
    service = ControlPlaneService()
    created = service.create_control(
        name="Execute Test",
        description="Test",
        module_type="GOVERNANCE",
        policy_type="ACCESS"
    )
    execution = service.execute_control(created["control_id"])
    assert execution is not None
    assert execution["status"] in ["COMPLETED", "FAILED"]

def test_create_workflow():
    """Test creating a workflow"""
    service = ControlPlaneService()
    workflow = service.create_workflow(
        name="Test Workflow",
        description="Multi-module workflow",
        control_ids=["ctrl-001", "ctrl-002"],
        modules=["FRAUD", "CTI"]
    )
    assert workflow is not None
    assert workflow["name"] == "Test Workflow"
    assert len(workflow["steps"]) == 2

def test_get_workflow():
    """Test getting a workflow"""
    service = ControlPlaneService()
    created = service.create_workflow(
        name="Get Workflow Test",
        description="Test",
        control_ids=["ctrl-001"],
        modules=["FRAUD"]
    )
    retrieved = service.get_workflow(created["workflow_id"])
    assert retrieved is not None
    assert retrieved["name"] == "Get Workflow Test"

def test_get_stats():
    """Test getting statistics"""
    service = ControlPlaneService()
    stats = service.get_stats()
    assert stats is not None
    assert "total_controls" in stats
    assert "total_executions" in stats

def test_get_dashboard():
    """Test dashboard data"""
    service = ControlPlaneService()
    dashboard = service.get_dashboard()
    assert dashboard is not None
    assert "stats" in dashboard
    assert "controls_count" in dashboard