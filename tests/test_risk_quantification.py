"""
Tests for Security Risk Quantification Platform
"""

import pytest

from src.risk_quantification.models import (
    RiskQuantification,
    BusinessExposure,
    ScenarioAnalysis,
    InvestmentRecommendation,
    RiskCategory,
    RiskLevel,
)
from src.risk_quantification.store import get_risk_store, reset_risk_store
from src.risk_quantification.service import RiskService


class TestRiskModels:
    """Tests for risk models."""

    def test_create_risk_quantification(self):
        """Test creating a risk quantification."""
        risk = RiskQuantification(
            name="Data Breach Risk",
            description="Risk of data breach",
            category=RiskCategory.CYBER,
            likelihood=0.7,
            impact=0.8,
        )
        assert risk.name == "Data Breach Risk"
        assert risk.category == RiskCategory.CYBER

    def test_create_business_exposure(self):
        """Test creating a business exposure."""
        exposure = BusinessExposure(
            risk_id="risk-001",
            business_unit="Engineering",
            revenue_impact_percentage=5.0,
        )
        assert exposure.business_unit == "Engineering"

    def test_create_scenario_analysis(self):
        """Test creating a scenario analysis."""
        scenario = ScenarioAnalysis(
            name="Ransomware Attack",
            description="Ransomware scenario",
            risk_ids=["risk-001", "risk-002"],
            probability=0.3,
        )
        assert len(scenario.risk_ids) == 2

    def test_create_investment_recommendation(self):
        """Test creating an investment recommendation."""
        rec = InvestmentRecommendation(
            title="Security Training",
            description="Security awareness training",
            investment_type="TRAINING",
            estimated_cost=50000.0,
            expected_risk_reduction=0.2,
        )
        assert rec.estimated_cost == 50000.0


class TestRiskStore:
    """Tests for risk store."""

    def setup_method(self):
        """Set up test store."""
        reset_risk_store()
        self.store = get_risk_store()

    def test_store_risk(self):
        """Test storing a risk."""
        risk = RiskQuantification(
            name="Test Risk",
            description="Test",
            category=RiskCategory.FRAUD,
            likelihood=0.5,
            impact=0.5,
        )
        self.store.store_risk(risk)
        retrieved = self.store.get_risk(risk.risk_id)
        assert retrieved is not None
        assert retrieved.name == "Test Risk"

    def test_get_risks_by_category(self):
        """Test getting risks by category."""
        self.store.store_risk(RiskQuantification(
            name="Cyber Risk",
            description="Test",
            category=RiskCategory.CYBER,
            likelihood=0.5,
            impact=0.5,
        ))
        results = self.store.get_risks_by_category(RiskCategory.CYBER)
        assert len(results) >= 1

    def test_get_risks_by_level(self):
        """Test getting risks by level."""
        risk = RiskQuantification(
            name="High Risk",
            description="Test",
            category=RiskCategory.CYBER,
            likelihood=0.9,
            impact=0.9,
        )
        risk.risk_level = RiskLevel.HIGH
        self.store.store_risk(risk)
        results = self.store.get_risks_by_level(RiskLevel.HIGH)
        assert len(results) >= 1

    def test_store_exposure(self):
        """Test storing a business exposure."""
        exposure = BusinessExposure(
            risk_id="risk-001",
            business_unit="Finance",
            revenue_impact_percentage=10.0,
        )
        self.store.store_exposure(exposure)
        results = self.store.get_exposures_by_risk("risk-001")
        assert len(results) >= 1

    def test_store_scenario(self):
        """Test storing a scenario."""
        scenario = ScenarioAnalysis(
            name="Test Scenario",
            description="Test",
            risk_ids=["risk-001"],
        )
        self.store.store_scenario(scenario)
        retrieved = self.store.get_scenario(scenario.scenario_id)
        assert retrieved is not None

    def test_get_metrics(self):
        """Test getting metrics."""
        self.store.store_risk(RiskQuantification(
            name="Test",
            description="Test",
            category=RiskCategory.CYBER,
            likelihood=0.5,
            impact=0.5,
        ))
        metrics = self.store.get_metrics()
        assert "total_risks" in metrics
        assert metrics["total_risks"] >= 1


class TestRiskService:
    """Tests for risk service."""

    def setup_method(self):
        """Set up test service."""
        reset_risk_store()
        self.service = RiskService()

    def test_quantify_risk(self):
        """Test quantifying a risk."""
        risk = self.service.quantify_risk(
            name="Fraud Risk",
            description="Fraudulent activity risk",
            category=RiskCategory.FRAUD,
            likelihood=0.6,
            impact=0.7,
        )
        assert risk.risk_score > 0
        assert risk.risk_level in RiskLevel

    def test_get_risk(self):
        """Test getting a risk."""
        quantified = self.service.quantify_risk(
            name="Test Risk",
            description="Test",
            category=RiskCategory.CYBER,
            likelihood=0.5,
            impact=0.5,
        )
        retrieved = self.service.get_risk(quantified.risk_id)
        assert retrieved is not None
        assert retrieved.name == "Test Risk"

    def test_get_risks_by_level(self):
        """Test getting risks by level."""
        risk = self.service.quantify_risk(
            name="High Risk",
            description="Test",
            category=RiskCategory.CYBER,
            likelihood=0.7,
            impact=0.7,
        )
        assert risk.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.MEDIUM]
        results = self.service.get_risks(level=risk.risk_level)
        assert len(results) >= 1

    def test_assess_business_exposure(self):
        """Test assessing business exposure."""
        risk = self.service.quantify_risk(
            name="Test",
            description="Test",
            category=RiskCategory.CYBER,
            likelihood=0.5,
            impact=0.5,
        )
        exposure = self.service.assess_business_exposure(
            risk_id=risk.risk_id,
            business_unit="Sales",
            revenue_impact_percentage=15.0,
        )
        assert exposure.business_unit == "Sales"

    def test_analyze_scenario(self):
        """Test analyzing a scenario."""
        risk1 = self.service.quantify_risk(
            name="Risk 1",
            description="Test",
            category=RiskCategory.CYBER,
            likelihood=0.5,
            impact=0.5,
        )
        risk2 = self.service.quantify_risk(
            name="Risk 2",
            description="Test",
            category=RiskCategory.FRAUD,
            likelihood=0.5,
            impact=0.5,
        )
        scenario = self.service.analyze_scenario(
            name="Combined Scenario",
            description="Test",
            risk_ids=[risk1.risk_id, risk2.risk_id],
        )
        assert scenario.total_financial_impact >= 0

    def test_recommend_investment(self):
        """Test recommending an investment."""
        rec = self.service.recommend_investment(
            title="Security Tools",
            description="New security tools",
            investment_type="TOOLS",
            estimated_cost=100000.0,
            expected_risk_reduction=0.3,
        )
        assert rec.roi > 0

    def test_get_metrics(self):
        """Test getting metrics."""
        self.service.quantify_risk(
            name="Test",
            description="Test",
            category=RiskCategory.CYBER,
            likelihood=0.7,
            impact=0.8,
        )
        metrics = self.service.get_metrics()
        assert metrics.total_risks >= 1
        assert metrics.critical_risks >= 0


class TestRiskIntegration:
    """Integration tests for risk quantification."""

    def setup_method(self):
        """Set up test environment."""
        reset_risk_store()
        self.service = RiskService()

    def test_full_risk_quantification_lifecycle(self):
        """Test complete risk quantification lifecycle."""
        risk = self.service.quantify_risk(
            name="Data Breach",
            description="Potential data breach",
            category=RiskCategory.CYBER,
            likelihood=0.6,
            impact=0.8,
            financial_impact_min=1000000.0,
            financial_impact_max=10000000.0,
            financial_impact_expected=5000000.0,
        )

        exposure = self.service.assess_business_exposure(
            risk_id=risk.risk_id,
            business_unit="IT",
            revenue_impact_percentage=10.0,
            customer_impact_count=1000,
        )
        assert exposure.exposure_id

        scenario = self.service.analyze_scenario(
            name="Data Breach Scenario",
            description="Scenario for data breach",
            risk_ids=[risk.risk_id],
            probability=0.6,
        )
        assert scenario.scenario_id

        investment = self.service.recommend_investment(
            title="Security Enhancement",
            description="Enhanced security controls",
            investment_type="CONTROLS",
            estimated_cost=500000.0,
            expected_risk_reduction=0.4,
            priority=RiskLevel.HIGH,
        )
        assert investment.recommendation_id

        metrics = self.service.get_metrics()
        assert metrics.total_risks >= 1
        assert metrics.total_financial_exposure > 0

        recommendations = self.service.get_recommendations()
        assert len(recommendations) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
