"""Tests for Investigation Universe Module"""
import pytest
from src.investigation_universe import InvestigationUniverseService, InvestigationStatus

def test_service_init():
    """Test service initialization"""
    service = InvestigationUniverseService()
    assert service is not None

def test_create_investigation():
    """Test creating an investigation"""
    service = InvestigationUniverseService()
    investigation = service.create_investigation(
        title="Test Investigation",
        description="Test description",
        priority=1
    )
    assert investigation is not None
    assert investigation["title"] == "Test Investigation"
    assert investigation["status"] == "INITIAL"

def test_get_investigation():
    """Test getting an investigation"""
    service = InvestigationUniverseService()
    created = service.create_investigation("Get Test", "Desc")
    retrieved = service.get_investigation(created["investigation_id"])
    assert retrieved is not None
    assert retrieved["title"] == "Get Test"

def test_get_all_investigations():
    """Test getting all investigations"""
    service = InvestigationUniverseService()
    service.create_investigation("Inv 1", "Desc", 1)
    service.create_investigation("Inv 2", "Desc", 2)
    investigations = service.get_all_investigations()
    assert len(investigations) >= 2

def test_update_investigation_status():
    """Test updating status"""
    service = InvestigationUniverseService()
    created = service.create_investigation("Status Test", "Desc")
    updated = service.update_investigation_status(
        created["investigation_id"], "ANALYZING"
    )
    assert updated is not None
    assert updated["status"] == "ANALYZING"

def test_add_evidence():
    """Test adding evidence"""
    service = InvestigationUniverseService()
    investigation = service.create_investigation("Evidence Test", "Desc")
    evidence = service.add_evidence(
        investigation_id=investigation["investigation_id"],
        evidence_type="NETWORK",
        description="Network logs",
        source="Firewall"
    )
    assert evidence is not None
    assert evidence["evidence_type"] == "NETWORK"

def test_get_investigation_evidence():
    """Test getting evidence for investigation"""
    service = InvestigationUniverseService()
    investigation = service.create_investigation("Evidence Get Test", "Desc")
    service.add_evidence(investigation["investigation_id"], "LOG", "Logs", "Server")
    evidence = service.get_investigation_evidence(investigation["investigation_id"])
    assert len(evidence) >= 1

def test_generate_hypothesis():
    """Test generating hypothesis"""
    service = InvestigationUniverseService()
    investigation = service.create_investigation("Hypothesis Test", "Desc")
    hypothesis = service.generate_hypothesis(
        investigation_id=investigation["investigation_id"],
        description="Possible fraud pattern detected",
        confidence="HIGH"
    )
    assert hypothesis is not None
    assert hypothesis["confidence"] == "HIGH"

def test_verify_hypothesis():
    """Test verifying hypothesis"""
    service = InvestigationUniverseService()
    investigation = service.create_investigation("Verify Test", "Desc")
    hypothesis = service.generate_hypothesis(
        investigation["investigation_id"], "Test hypothesis", "MEDIUM"
    )
    verified = service.verify_hypothesis(hypothesis["hypothesis_id"])
    assert verified is not None
    assert verified["verified"] is True

def test_add_correlation():
    """Test adding correlation"""
    service = InvestigationUniverseService()
    investigation = service.create_investigation("Correlation Test", "Desc")
    correlation = service.add_correlation(
        investigation_id=investigation["investigation_id"],
        entity_type="ACCOUNT",
        entity_id="acc-123",
        related_entities=["acc-456", "acc-789"],
        correlation_type="TRANSFER",
        strength=0.9
    )
    assert correlation is not None
    assert correlation["strength"] == 0.9

def test_generate_narrative():
    """Test narrative generation"""
    service = InvestigationUniverseService()
    investigation = service.create_investigation("Narrative Test", "Desc")
    service.add_evidence(investigation["investigation_id"], "LOG", "Logs", "Server")
    service.generate_hypothesis(investigation["investigation_id"], "Test", "HIGH")
    
    narrative = service.generate_narrative(investigation["investigation_id"])
    assert narrative is not None
    assert "narrative" in narrative
    assert "summary" in narrative

def test_get_dashboard():
    """Test dashboard data"""
    service = InvestigationUniverseService()
    service.create_investigation("Dashboard Test", "Desc")
    dashboard = service.get_dashboard()
    assert dashboard is not None
    assert "total_investigations" in dashboard
    assert "total_evidence" in dashboard