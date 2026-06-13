"""Tests for MetaBrain Module"""
import pytest
from datetime import datetime
from src.metabrain import (
    MetaBrainService,
    IntelligenceSignal,
    AnalysisType,
    IntelligenceLevel
)

def test_metabrain_service_init():
    """Test MetaBrain service initialization"""
    service = MetaBrainService()
    assert service is not None
    assert service.store is not None
    assert service.reasoning_engine is not None
    assert service.recommendation_engine is not None
    assert service.planner is not None

def test_add_signal():
    """Test adding intelligence signal"""
    service = MetaBrainService()
    signal = service.add_signal(
        signal_type="FRAUD",
        source_module="fraud_detection",
        severity="HIGH",
        description="Suspicious transaction pattern detected",
        confidence=0.85
    )
    assert signal is not None
    assert signal.signal_type == AnalysisType.FRAUD
    assert signal.severity == "HIGH"
    assert signal.confidence == 0.85

def test_analyze():
    """Test cross-domain analysis"""
    service = MetaBrainService()
    
    # Add multiple signals
    service.add_signal(
        signal_type="FRAUD",
        source_module="fraud_detection",
        severity="HIGH",
        description="Fraud signal 1",
        confidence=0.9
    )
    service.add_signal(
        signal_type="CYBER_THREAT",
        source_module="cti_system",
        severity="CRITICAL",
        description="Cyber threat detected",
        confidence=0.95
    )
    
    # Analyze
    result = service.analyze()
    assert result is not None
    assert "insights" in result
    assert "recommendations" in result
    assert "threat_landscape" in result
    assert result["threat_landscape"]["threat_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def test_get_recommendations():
    """Test getting recommendations"""
    service = MetaBrainService()
    service.add_signal(
        signal_type="FRAUD",
        source_module="fraud_detection",
        severity="HIGH",
        description="Test fraud signal",
        confidence=0.8
    )
    service.analyze()
    
    recommendations = service.get_recommendations()
    assert isinstance(recommendations, list)

def test_create_forecast():
    """Test creating forecast"""
    service = MetaBrainService()
    forecast = service.create_forecast(
        forecast_type="FRAUD_TREND",
        prediction="Increase in account takeover attacks",
        timeframe="30 days",
        confidence=0.75,
        affected_sectors=["Banking", "E-commerce"]
    )
    assert forecast is not None
    assert forecast.forecast_type == "FRAUD_TREND"
    assert "account takeover" in forecast.prediction.lower()

def test_create_strategy():
    """Test creating strategy"""
    service = MetaBrainService()
    strategy = service.create_strategy(
        strategy_type="FRAUD_PREVENTION",
        name="Q4 Fraud Defense Strategy",
        description="Comprehensive fraud prevention plan"
    )
    assert strategy is not None
    assert strategy.name == "Q4 Fraud Defense Strategy"
    assert len(strategy.objectives) > 0
    assert len(strategy.phases) > 0

def test_get_dashboard():
    """Test dashboard data"""
    service = MetaBrainService()
    service.add_signal(
        signal_type="CYBER_THREAT",
        source_module="siem",
        severity="HIGH",
        description="Threat detected",
        confidence=0.9
    )
    
    dashboard = service.get_dashboard()
    assert dashboard is not None
    assert "total_signals" in dashboard
    assert dashboard["total_signals"] >= 1
    assert "threat_landscape" in dashboard

def test_intelligence_signal_to_dict():
    """Test signal serialization"""
    signal = IntelligenceSignal(
        signal_id="test-123",
        signal_type=AnalysisType.FRAUD,
        source_module="test",
        severity="HIGH",
        description="Test",
        confidence=0.8
    )
    data = signal.to_dict()
    assert data["signal_id"] == "test-123"
    assert data["signal_type"] == "FRAUD"
    assert "timestamp" in data