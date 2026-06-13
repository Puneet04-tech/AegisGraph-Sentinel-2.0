"""Tests for Security Universe Module"""
import pytest
from src.security_universe import (
    SecurityUniverseService,
    TeamType,
    IncidentSeverity,
    WorkflowStatus
)

def test_service_init():
    """Test service initialization"""
    service = SecurityUniverseService()
    assert service is not None
    assert service.engine is not None
    assert len(service.engine.teams) > 0

def test_add_team():
    """Test adding a team"""
    service = SecurityUniverseService()
    team = service.add_team({
        "name": "Test Team",
        "team_type": "RISK_MANAGEMENT",
        "members": ["user1", "user2"],
        "responsibilities": ["Risk assessment"],
        "contact_email": "test@company.com"
    })
    assert team is not None
    assert team["name"] == "Test Team"
    assert team["team_type"] == "RISK_MANAGEMENT"

def test_get_teams():
    """Test getting all teams"""
    service = SecurityUniverseService()
    teams = service.get_teams()
    assert len(teams) > 0
    assert teams[0]["team_type"] in [t.value for t in TeamType]

def test_create_incident():
    """Test creating an incident"""
    service = SecurityUniverseService()
    incident = service.create_incident(
        title="Cross-team security incident",
        description="Test incident affecting multiple teams",
        severity="P2_HIGH",
        source_teams=["SOC", "FRAUD_OPS"],
        assigned_teams=["SOC", "FRAUD_OPS"]
    )
    assert incident is not None
    assert incident["title"] == "Cross-team security incident"
    assert incident["severity"] == "P2_HIGH"
    assert "SOC" in incident["source_teams"]

def test_link_incidents():
    """Test linking incidents"""
    service = SecurityUniverseService()
    inc1 = service.create_incident(
        title="Incident 1",
        description="First incident",
        severity="P3_MEDIUM",
        source_teams=["SOC"]
    )
    inc2 = service.create_incident(
        title="Incident 2",
        description="Second incident",
        severity="P3_MEDIUM",
        source_teams=["FRAUD_OPS"]
    )
    
    result = service.link_incidents(inc1["incident_id"], inc2["incident_id"])
    assert result is True

def test_create_collaboration():
    """Test creating collaboration record"""
    service = SecurityUniverseService()
    incident = service.create_incident(
        title="Collaboration Test",
        description="Test",
        severity="P4_LOW",
        source_teams=["SOC"]
    )
    
    collaboration = service.create_collaboration(
        incident_id=incident["incident_id"],
        from_team="SOC",
        to_team="FRAUD_OPS",
        action="Information sharing",
        notes="Shared threat intelligence",
        created_by="analyst1"
    )
    assert collaboration is not None
    assert collaboration["action"] == "Information sharing"

def test_update_incident_status():
    """Test updating incident status"""
    service = SecurityUniverseService()
    incident = service.create_incident(
        title="Status Test",
        description="Test",
        severity="P3_MEDIUM",
        source_teams=["SOC"]
    )
    
    updated = service.update_incident_status(incident["incident_id"], "IN_PROGRESS")
    assert updated["status"] == "IN_PROGRESS"

def test_get_incident_summary():
    """Test getting incident summary"""
    service = SecurityUniverseService()
    service.create_incident(
        title="Test 1",
        description="Test",
        severity="P1_CRITICAL",
        source_teams=["SOC"]
    )
    service.create_incident(
        title="Test 2",
        description="Test",
        severity="P2_HIGH",
        source_teams=["FRAUD_OPS"]
    )
    
    summary = service.get_incident_summary()
    assert summary["total_incidents"] == 2
    assert "by_severity" in summary
    assert "by_team" in summary

def test_universe_analytics():
    """Test universe analytics"""
    service = SecurityUniverseService()
    analytics = service.get_universe_analytics()
    assert "total_teams" in analytics
    assert "total_incidents" in analytics
    assert analytics["total_teams"] > 0