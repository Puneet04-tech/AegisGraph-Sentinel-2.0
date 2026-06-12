"""
Tests for Financial Crime Command Center.
"""

import asyncio
import pytest
from datetime import datetime, timezone

from src.financial_crime_command import (
    Alert,
    AlertStatus,
    CaseStatus,
    CrimeCase,
    CrimeType,
    ThreatLevel,
    FinancialCrimeStore,
    get_financial_crime_store,
    reset_financial_crime_store,
    CrimeIntelligenceEngine,
    CaseCorrelationEngine,
    RiskPrioritizationEngine,
    ThreatFusionEngine,
    FinancialCrimeCommandCenter,
)


class TestModels:
    """Test data models."""

    def test_crime_case_creation(self):
        """Test crime case creation."""
        case = CrimeCase(
            case_id="case-1",
            title="Test Case",
            description="Test financial crime case",
            crime_type=CrimeType.FRAUD,
        )
        assert case.case_id == "case-1"
        assert case.crime_type == CrimeType.FRAUD
        assert case.status == CaseStatus.CREATED

    def test_alert_creation(self):
        """Test alert creation."""
        alert = Alert(
            alert_id="alert-1",
            title="Suspicious Activity",
            description="High-value transaction",
            crime_type=CrimeType.MONEY_LAUNDERING,
            threat_level=ThreatLevel.HIGH,
        )
        assert alert.alert_id == "alert-1"
        assert alert.threat_level == ThreatLevel.HIGH
        assert alert.status == AlertStatus.TRIGGERED


class TestStore:
    """Test financial crime store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_financial_crime_store()
        self.store = get_financial_crime_store()

    def test_case_storage(self):
        """Test storing and retrieving cases."""
        case = CrimeCase(
            case_id="case-1",
            title="Test",
            description="Test",
            crime_type=CrimeType.FRAUD,
        )
        self.store.store_case(case)
        
        retrieved = self.store.get_case("case-1")
        assert retrieved is not None
        assert retrieved.case_id == "case-1"

    def test_get_cases_by_status(self):
        """Test getting cases by status."""
        case = CrimeCase(
            case_id="case-1",
            title="Test",
            description="Test",
            crime_type=CrimeType.FRAUD,
            status=CaseStatus.IN_PROGRESS,
        )
        self.store.store_case(case)
        
        cases = self.store.get_cases_by_status("in_progress")
        assert len(cases) == 1

    def test_dashboard_metrics(self):
        """Test dashboard metrics."""
        case = CrimeCase(
            case_id="case-1",
            title="Test",
            description="Test",
            crime_type=CrimeType.FRAUD,
        )
        self.store.store_case(case)
        
        metrics = self.store.get_dashboard_metrics()
        assert metrics["total_cases"] == 1
        assert metrics["open_cases"] == 1


class TestIntelligenceEngine:
    """Test crime intelligence engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_financial_crime_store()

    def test_analyze_case(self):
        """Test case analysis."""
        engine = CrimeIntelligenceEngine()
        case = CrimeCase(
            case_id="case-1",
            title="Critical Fraud",
            description="High priority fraud case",
            crime_type=CrimeType.FRAUD,
            threat_level=ThreatLevel.CRITICAL,
            priority_score=0.9,
        )
        
        result = asyncio.run(engine.analyze_case(case))
        assert "risk_factors" in result
        assert len(result["risk_factors"]) > 0

    def test_detect_patterns(self):
        """Test pattern detection."""
        store = get_financial_crime_store()
        
        for i in range(5):
            case = CrimeCase(
                case_id=f"case-{i}",
                title=f"Fraud Case {i}",
                description="Test",
                crime_type=CrimeType.FRAUD,
            )
            store.store_case(case)
        
        engine = CrimeIntelligenceEngine()
        patterns = engine.detect_crime_patterns()
        assert isinstance(patterns, list)


class TestCorrelationEngine:
    """Test case correlation engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_financial_crime_store()

    def test_find_correlations(self):
        """Test finding correlations."""
        store = get_financial_crime_store()
        
        case1 = CrimeCase(
            case_id="case-1",
            title="Fraud A",
            description="Test",
            crime_type=CrimeType.FRAUD,
            entity_ids=["entity-1", "entity-2"],
        )
        case2 = CrimeCase(
            case_id="case-2",
            title="Fraud B",
            description="Test",
            crime_type=CrimeType.FRAUD,
            entity_ids=["entity-1", "entity-3"],
        )
        
        store.store_case(case1)
        store.store_case(case2)
        
        engine = CaseCorrelationEngine()
        correlations = engine.find_correlations("case-1")
        
        assert len(correlations) > 0
        assert correlations[0].target_case_id == "case-2"

    def test_link_cases(self):
        """Test linking cases."""
        store = get_financial_crime_store()
        
        case1 = CrimeCase(
            case_id="case-1",
            title="Test A",
            description="Test",
            crime_type=CrimeType.FRAUD,
        )
        case2 = CrimeCase(
            case_id="case-2",
            title="Test B",
            description="Test",
            crime_type=CrimeType.FRAUD,
        )
        
        store.store_case(case1)
        store.store_case(case2)
        
        engine = CaseCorrelationEngine()
        link = engine.link_cases("case-1", "case-2", "shared_entities")
        
        assert link is not None
        assert link.confidence > 0


class TestPrioritizationEngine:
    """Test risk prioritization engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_financial_crime_store()

    def test_calculate_priority(self):
        """Test priority calculation."""
        engine = RiskPrioritizationEngine()
        
        case = CrimeCase(
            case_id="case-1",
            title="Critical Case",
            description="Test",
            crime_type=CrimeType.FRAUD,
            threat_level=ThreatLevel.CRITICAL,
            financial_impact=500000,
        )
        
        score = engine.calculate_priority_score(case)
        assert score.total_score > 0.5

    def test_prioritize_queue(self):
        """Test queue prioritization."""
        store = get_financial_crime_store()
        
        cases = []
        for i in range(5):
            case = CrimeCase(
                case_id=f"case-{i}",
                title=f"Case {i}",
                description="Test",
                crime_type=CrimeType.FRAUD,
                priority_score=i / 10,
            )
            store.store_case(case)
            cases.append(case)
        
        engine = RiskPrioritizationEngine()
        results = engine.prioritize_queue(cases)
        
        assert len(results) == 5
        assert results[0].priority_rank == 1


class TestThreatFusionEngine:
    """Test threat fusion engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_financial_crime_store()

    def test_add_threat(self):
        """Test adding threat."""
        engine = ThreatFusionEngine()
        threat = engine.add_threat(
            indicator_type="ip",
            value="192.168.1.1",
            confidence=0.8,
            source="test",
            tags=["malicious", "fraud"],
        )
        
        assert threat.indicator_id is not None
        assert threat.confidence == 0.8

    def test_get_threat_summary(self):
        """Test threat summary."""
        engine = ThreatFusionEngine()
        engine.add_threat("ip", "192.168.1.1", 0.8, "test")
        
        summary = engine.get_threat_summary()
        assert summary["total_threats"] == 1


class TestFinancialCrimeCommandCenter:
    """Test main command center service."""

    def setup_method(self):
        """Reset store before each test."""
        reset_financial_crime_store()
        self.service = FinancialCrimeCommandCenter()

    def test_create_case(self):
        """Test creating a case."""
        result = asyncio.run(self.service.create_case(
            title="Test Fraud Case",
            description="Testing case creation",
            crime_type="fraud",
        ))
        
        assert "case_id" in result
        assert result["status"] == "created"

    def test_get_dashboard(self):
        """Test getting dashboard."""
        result = asyncio.run(self.service.get_dashboard())
        
        assert "total_cases" in result
        assert "open_cases" in result

    def test_get_investigations(self):
        """Test getting investigations."""
        asyncio.run(self.service.create_case(
            title="Test",
            description="Test",
            crime_type="fraud",
        ))
        
        investigations = asyncio.run(self.service.get_investigations())
        assert isinstance(investigations, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])