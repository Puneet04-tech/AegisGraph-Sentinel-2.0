"""Tests for Threat Strategy Module"""
import pytest
from src.threat_strategy import (
    ThreatStrategyService,
    ThreatCategory,
    ThreatLevel
)

def test_service_init():
    """Test service initialization"""
    service = ThreatStrategyService()
    assert service is not None
    assert service.planner is not None
    assert service.simulator is not None

def test_create_strategy():
    """Test creating a strategy"""
    service = ThreatStrategyService()
    strategy = service.create_strategy(
        name="Q4 Cyber Defense Strategy",
        description="Comprehensive cyber defense plan",
        threat_category="CYBER",
        threat_level="HIGH",
        threat_description="Increased APT activity",
        affected_areas=["Network", "Endpoints", "Cloud"],
        likelihood=0.8,
        impact=0.9,
        timeline_days=90
    )
    assert strategy is not None
    assert strategy["name"] == "Q4 Cyber Defense Strategy"
    assert strategy["threat_assessment"]["threat_level"] == "HIGH"

def test_get_strategy():
    """Test getting a strategy"""
    service = ThreatStrategyService()
    created = service.create_strategy(
        name="Test Strategy",
        description="Test description",
        threat_category="FRAUD",
        threat_level="MEDIUM",
        threat_description="Fraud test",
        affected_areas=["Transactions"],
        likelihood=0.5,
        impact=0.6
    )
    
    retrieved = service.get_strategy(created["strategy_id"])
    assert retrieved is not None
    assert retrieved["name"] == "Test Strategy"

def test_approve_strategy():
    """Test approving a strategy"""
    service = ThreatStrategyService()
    created = service.create_strategy(
        name="Test Strategy",
        description="Test",
        threat_category="FRAUD",
        threat_level="LOW",
        threat_description="Test",
        affected_areas=["Test"],
        likelihood=0.3,
        impact=0.4
    )
    
    approved = service.approve_strategy(created["strategy_id"])
    assert approved["status"] == "APPROVED"

def test_simulate_attack():
    """Test attack simulation"""
    service = ThreatStrategyService()
    result = service.simulate_attack(
        scenario_id="apt-attack",
        defense_controls=["SIEM", "MFA", "EDR"]
    )
    assert result is not None
    assert "risk_level" in result
    assert result["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def test_generate_forecast():
    """Test forecast generation"""
    service = ThreatStrategyService()
    forecast = service.generate_forecast(
        threat_type="FRAUD",
        timeframe_days=30
    )
    assert forecast is not None
    assert forecast["threat_type"] == "FRAUD"
    assert "prediction" in forecast
    assert "confidence" in forecast

def test_generate_roadmap():
    """Test roadmap generation"""
    service = ThreatStrategyService()
    created = service.create_strategy(
        name="Test Strategy",
        description="Test",
        threat_category="CYBER",
        threat_level="HIGH",
        threat_description="Test",
        affected_areas=["Network"],
        likelihood=0.7,
        impact=0.8
    )
    
    roadmap = service.generate_roadmap(created["strategy_id"])
    assert roadmap is not None
    assert "phases" in roadmap
    assert len(roadmap["phases"]) > 0

def test_get_available_scenarios():
    """Test getting available scenarios"""
    service = ThreatStrategyService()
    scenarios = service.get_available_scenarios()
    assert len(scenarios) > 0
    assert scenarios[0]["scenario_id"] is not None