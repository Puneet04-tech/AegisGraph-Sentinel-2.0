"""
Tests for Autonomous Security Decision Engine
"""

import pytest

from src.decision_intelligence.models import (
    SecurityRecommendation,
    MitigationAction,
    RiskDecision,
    ExplainabilityRecord,
    GovernanceDecision,
    DecisionType,
    DecisionPriority,
    DecisionStatus,
)
from src.decision_intelligence.store import get_decision_store, reset_decision_store
from src.decision_intelligence.service import DecisionService


class TestDecisionModels:
    """Tests for decision models."""

    def test_create_recommendation(self):
        """Test creating a recommendation."""
        rec = SecurityRecommendation(
            title="Enable MFA",
            description="Enable multi-factor authentication",
            decision_type=DecisionType.RECOMMENDATION,
            priority=DecisionPriority.HIGH,
            confidence=0.9,
        )
        assert rec.title == "Enable MFA"
        assert rec.priority == DecisionPriority.HIGH

    def test_create_mitigation_action(self):
        """Test creating a mitigation action."""
        action = MitigationAction(
            recommendation_id="rec-001",
            title="Apply security patch",
            description="Apply CVE patch",
            action_type="PATCH",
            priority=DecisionPriority.HIGH,
        )
        assert action.recommendation_id == "rec-001"
        assert action.status == "PENDING"

    def test_create_risk_decision(self):
        """Test creating a risk decision."""
        decision = RiskDecision(
            context="Data breach risk",
            risk_factors={"likelihood": 0.7, "impact": 0.8},
            decision="Implement encryption",
            reasoning="High risk requires encryption",
            confidence=0.9,
        )
        assert decision.decision == "Implement encryption"
        assert decision.confidence == 0.9

    def test_create_explainability_record(self):
        """Test creating an explainability record."""
        record = ExplainabilityRecord(
            decision_id="dec-001",
            explanation="Based on risk analysis",
            factors=[{"factor": "risk_score", "value": 0.8}],
        )
        assert record.decision_id == "dec-001"

    def test_create_governance_decision(self):
        """Test creating a governance decision."""
        decision = GovernanceDecision(
            title="Security Policy Update",
            description="Update password policy",
            decision_type=DecisionType.GOVERNANCE,
            rationale="Compliance requirement",
        )
        assert decision.title == "Security Policy Update"


class TestDecisionStore:
    """Tests for decision store."""

    def setup_method(self):
        """Set up test store."""
        reset_decision_store()
        self.store = get_decision_store()

    def test_store_recommendation(self):
        """Test storing a recommendation."""
        rec = SecurityRecommendation(
            title="Test Recommendation",
            description="Test",
            decision_type=DecisionType.RECOMMENDATION,
        )
        self.store.store_recommendation(rec)
        retrieved = self.store.get_recommendation(rec.recommendation_id)
        assert retrieved is not None
        assert retrieved.title == "Test Recommendation"

    def test_get_recommendations_by_type(self):
        """Test getting recommendations by type."""
        self.store.store_recommendation(SecurityRecommendation(
            title="Test",
            description="Test",
            decision_type=DecisionType.MITIGATION,
        ))
        results = self.store.get_recommendations_by_type(DecisionType.MITIGATION)
        assert len(results) >= 1

    def test_get_recommendations_by_priority(self):
        """Test getting recommendations by priority."""
        self.store.store_recommendation(SecurityRecommendation(
            title="Test",
            description="Test",
            decision_type=DecisionType.RECOMMENDATION,
            priority=DecisionPriority.HIGH,
        ))
        results = self.store.get_recommendations_by_priority(DecisionPriority.HIGH)
        assert len(results) >= 1

    def test_store_mitigation_action(self):
        """Test storing a mitigation action."""
        action = MitigationAction(
            recommendation_id="rec-001",
            title="Test Action",
            description="Test",
            action_type="PATCH",
            priority=DecisionPriority.MEDIUM,
        )
        self.store.store_mitigation_action(action)
        results = self.store.get_mitigation_actions_by_recommendation("rec-001")
        assert len(results) >= 1

    def test_store_risk_decision(self):
        """Test storing a risk decision."""
        decision = RiskDecision(
            context="Test",
            risk_factors={"risk": 0.5},
            decision="Test decision",
        )
        self.store.store_risk_decision(decision)
        retrieved = self.store.get_risk_decision(decision.decision_id)
        assert retrieved is not None

    def test_get_metrics(self):
        """Test getting metrics."""
        self.store.store_recommendation(SecurityRecommendation(
            title="Test",
            description="Test",
            decision_type=DecisionType.RECOMMENDATION,
        ))
        metrics = self.store.get_metrics()
        assert "total_recommendations" in metrics
        assert metrics["total_recommendations"] >= 1


class TestDecisionService:
    """Tests for decision service."""

    def setup_method(self):
        """Set up test service."""
        reset_decision_store()
        self.service = DecisionService()

    def test_generate_recommendation(self):
        """Test generating a recommendation."""
        rec = self.service.generate_recommendation(
            title="Security Enhancement",
            description="Enhance security controls",
            decision_type=DecisionType.RECOMMENDATION,
            confidence=0.9,
            risk_score=0.8,
        )
        assert rec.recommendation_id is not None
        assert rec.priority in DecisionPriority

    def test_get_recommendation(self):
        """Test getting a recommendation."""
        generated = self.service.generate_recommendation(
            title="Test Recommendation",
            description="Test",
            decision_type=DecisionType.RECOMMENDATION,
        )
        retrieved = self.service.get_recommendation(generated.recommendation_id)
        assert retrieved is not None
        assert retrieved.title == "Test Recommendation"

    def test_approve_recommendation(self):
        """Test approving a recommendation."""
        rec = self.service.generate_recommendation(
            title="Test",
            description="Test",
            decision_type=DecisionType.RECOMMENDATION,
        )
        approved = self.service.approve_recommendation(
            rec.recommendation_id,
            approver="security-team",
        )
        assert approved is not None
        assert approved.status == DecisionStatus.APPROVED

    def test_create_mitigation_action(self):
        """Test creating a mitigation action."""
        rec = self.service.generate_recommendation(
            title="Test",
            description="Test",
            decision_type=DecisionType.MITIGATION,
        )
        action = self.service.create_mitigation_action(
            recommendation_id=rec.recommendation_id,
            title="Apply Patch",
            description="Apply security patch",
            action_type="PATCH",
        )
        assert action.recommendation_id == rec.recommendation_id

    def test_make_risk_decision(self):
        """Test making a risk decision."""
        decision = self.service.make_risk_decision(
            context="Critical system vulnerability",
            risk_factors={"likelihood": 0.8, "impact": 0.9},
            decision="Immediate patching required",
            reasoning="High risk scenario",
            confidence=0.95,
        )
        assert decision.decision_id is not None
        assert decision.confidence == 0.95

    def test_explain_decision(self):
        """Test explaining a decision."""
        decision = self.service.make_risk_decision(
            context="Test",
            risk_factors={"risk": 0.5},
            decision="Test decision",
        )
        explanation = self.service.explain_decision(
            decision_id=decision.decision_id,
            explanation="Based on risk factors",
            factors=[{"factor": "risk", "value": 0.5}],
        )
        assert explanation.decision_id == decision.decision_id

    def test_create_governance_decision(self):
        """Test creating a governance decision."""
        decision = self.service.create_governance_decision(
            title="Policy Update",
            description="Update security policy",
            decision_type=DecisionType.GOVERNANCE,
            rationale="Compliance",
        )
        assert decision.decision_id is not None

    def test_get_metrics(self):
        """Test getting metrics."""
        self.service.generate_recommendation(
            title="Test",
            description="Test",
            decision_type=DecisionType.RECOMMENDATION,
            confidence=0.8,
        )
        metrics = self.service.get_metrics()
        assert metrics.total_decisions >= 1
        assert metrics.average_confidence > 0


class TestDecisionIntegration:
    """Integration tests for decision engine."""

    def setup_method(self):
        """Set up test environment."""
        reset_decision_store()
        self.service = DecisionService()

    def test_full_decision_lifecycle(self):
        """Test complete decision lifecycle."""
        rec = self.service.generate_recommendation(
            title="Enable Encryption",
            description="Enable encryption for sensitive data",
            decision_type=DecisionType.MITIGATION,
            confidence=0.9,
            risk_score=0.85,
            expected_outcome="Reduced data breach risk",
        )

        action = self.service.create_mitigation_action(
            recommendation_id=rec.recommendation_id,
            title="Implement Encryption",
            description="Implement AES-256 encryption",
            action_type="ENCRYPTION",
            priority=DecisionPriority.HIGH,
        )
        assert action.action_id

        decision = self.service.make_risk_decision(
            context="Encryption implementation decision",
            risk_factors={
                "data_sensitivity": 0.9,
                "compliance_requirement": 0.8,
                "implementation_cost": 0.3,
            },
            decision="Proceed with encryption implementation",
            reasoning="High data sensitivity requires encryption",
            confidence=0.92,
        )
        assert decision.decision_id

        explanation = self.service.explain_decision(
            decision_id=decision.decision_id,
            explanation="Encryption is required due to high data sensitivity",
            factors=[
                {"factor": "data_sensitivity", "impact": "positive"},
                {"factor": "compliance", "impact": "positive"},
            ],
        )
        assert explanation.record_id

        governance = self.service.create_governance_decision(
            title="Encryption Policy",
            description="Policy for encryption implementation",
            decision_type=DecisionType.GOVERNANCE,
            rationale="Security and compliance",
        )
        assert governance.decision_id

        metrics = self.service.get_metrics()
        assert metrics.total_decisions >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
