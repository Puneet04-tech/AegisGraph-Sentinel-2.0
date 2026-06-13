"""Tests for Response Grid Module"""
import pytest
from src.response_grid import ResponseGridService, Severity, IncidentStatus

def test_service_init():
    """Test service initialization"""
    service = ResponseGridService()
    assert service is not None
    assert len(service.playbooks) >= 2
    assert len(service.partners) >= 3

def test_create_incident():
    """Test creating an incident"""
    service = ResponseGridService()
    incident = service.create_incident(
        title="Test Incident",
        description="Test description",
        severity="HIGH",
        tags=["test"]
    )
    assert incident is not None
    assert incident["title"] == "Test Incident"
    assert incident["severity"] == "HIGH"

def test_get_incident():
    """Test getting an incident"""
    service = ResponseGridService()
    created = service.create_incident("Get Test", "Description", "MEDIUM")
    retrieved = service.get_incident(created["incident_id"])
    assert retrieved is not None
    assert retrieved["title"] == "Get Test"

def test_get_all_incidents():
    """Test getting all incidents"""
    service = ResponseGridService()
    service.create_incident("Incident 1", "Desc", "LOW")
    service.create_incident("Incident 2", "Desc", "HIGH")
    incidents = service.get_all_incidents()
    assert len(incidents) >= 2

def test_update_incident_status():
    """Test updating incident status"""
    service = ResponseGridService()
    created = service.create_incident("Status Test", "Desc", "CRITICAL")
    updated = service.update_incident_status(created["incident_id"], "INVESTIGATING")
    assert updated is not None
    assert updated["status"] == "INVESTIGATING"

def test_link_incidents():
    """Test linking incidents"""
    service = ResponseGridService()
    inc1 = service.create_incident("Inc 1", "Desc", "HIGH")
    inc2 = service.create_incident("Inc 2", "Desc", "MEDIUM")
    result = service.link_incidents(inc1["incident_id"], inc2["incident_id"])
    assert result is True

def test_create_remediation():
    """Test creating remediation action"""
    service = ResponseGridService()
    incident = service.create_incident("Remediation Test", "Desc", "CRITICAL")
    remediation = service.create_remediation(
        incident_id=incident["incident_id"],
        action_type="ISOLATE",
        description="Isolate affected system",
        assigned_to="analyst@example.com"
    )
    assert remediation is not None
    assert remediation["status"] == "PENDING"

def test_execute_remediation():
    """Test executing remediation"""
    service = ResponseGridService()
    incident = service.create_incident("Execute Test", "Desc", "HIGH")
    action = service.create_remediation(incident["incident_id"], "BLOCK", "Block IP")
    executed = service.execute_remediation(action["action_id"])
    assert executed is not None
    assert executed["status"] == "COMPLETED"

def test_get_playbooks():
    """Test getting playbooks"""
    service = ResponseGridService()
    playbooks = service.get_all_playbooks()
    assert len(playbooks) >= 2

def test_get_dashboard():
    """Test dashboard data"""
    service = ResponseGridService()
    service.create_incident("Dashboard Test", "Desc", "LOW")
    dashboard = service.get_dashboard()
    assert dashboard is not None
    assert "total_incidents" in dashboard
    assert "total_partners" in dashboard