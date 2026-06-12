"""
Tests for AI Decision Intelligence Fabric Module
"""
import pytest
from datetime import datetime, timezone

from src.decision_fabric import (
    DecisionEngine,
    get_decision_engine,
    AIReasoningLayer,
    PolicyIntelligenceEngine,
    Decision,
    DecisionType,
    DecisionStatus,
    DecisionConfidence,
    PolicyRule,
)


class TestAIReasoningLayer:
    """Tests for AIReasoningLayer."""
    
    def setup_method(self):
        self.reasoning = AIReasoningLayer()
    
    def test_evaluate_low_risk(self):
        """Test evaluating low-risk context."""
        context = {"amount": 100, "risk_score": 0.1}
        result = self.reasoning.evaluate(context, DecisionType.TRANSACTION_APPROVAL)
        
        assert "factors" in result
        assert "confidence" in result
        assert result["confidence"] >= 0.5
    
    def test_evaluate_high_risk(self):
        """Test evaluating high-risk context."""
        context = {
            "amount": 50000,
            "new_recipient": True,
            "velocity_anomaly": True,
            "high_risk_country": True,
        }
        result = self.reasoning.evaluate(context, DecisionType.FRAUD_APPROVAL)
        
        assert len(result["factors"]) >= 2
        assert result["risk_indicators"] >= 2


class TestPolicyIntelligenceEngine:
    """Tests for PolicyIntelligenceEngine."""
    
    def setup_method(self):
        self.engine = PolicyIntelligenceEngine()
    
    def test_initialization(self):
        """Test engine initialization."""
        assert len(self.engine.rules) > 0
    
    def test_evaluate_rules(self):
        """Test rule evaluation."""
        context = {"amount": 15000}
        rules = self.engine.evaluate_rules(context, DecisionType.TRANSACTION_APPROVAL)
        
        assert len(rules) >= 1
    
    def test_matches_conditions(self):
        """Test condition matching."""
        context = {"amount": 20000, "fraud_score": 0.9}
        
        result = self.engine._matches_conditions(
            context,
            [{"field": "amount", "operator": ">", "value": 10000}],
        )
        assert result is True
        
        result = self.engine._matches_conditions(
            context,
            [{"field": "fraud_score", "operator": ">=", "value": 0.8}],
        )
        assert result is True
    
    def test_add_rule(self):
        """Test adding a rule."""
        rule = PolicyRule(
            rule_id="test-rule",
            name="Test Rule",
            description="Test description",
            decision_type=DecisionType.RISK_ASSESSMENT,
            conditions=[],
            actions=["APPROVE"],
        )
        
        rule_id = self.engine.add_rule(rule)
        assert rule_id == "test-rule"


class TestDecisionEngine:
    """Tests for DecisionEngine."""
    
    def setup_method(self):
        self.engine = DecisionEngine()
    
    def test_evaluate_approval(self):
        """Test evaluating approval decision."""
        decision = self.engine.evaluate(
            decision_type=DecisionType.TRANSACTION_APPROVAL,
            context={"amount": 100, "risk_score": 0.1},
        )
        
        assert decision is not None
        assert decision.outcome in ["APPROVED", "ESCALATED", "NEEDS_REVIEW"]
    
    def test_evaluate_rejection(self):
        """Test evaluating rejection decision."""
        decision = self.engine.evaluate(
            decision_type=DecisionType.FRAUD_APPROVAL,
            context={"fraud_score": 0.95},
        )
        
        assert decision is not None
        assert decision.decision_type == DecisionType.FRAUD_APPROVAL
    
    def test_get_decision(self):
        """Test getting a decision."""
        decision = self.engine.evaluate(
            decision_type=DecisionType.AML_ALERT,
            context={"aml_score": 0.8},
        )
        
        retrieved = self.engine.get_decision(decision.decision_id)
        assert retrieved is not None
        assert retrieved.decision_id == decision.decision_id
    
    def test_explain_decision(self):
        """Test explaining a decision."""
        decision = self.engine.evaluate(
            decision_type=DecisionType.TRANSACTION_APPROVAL,
            context={"amount": 5000},
        )
        
        explanation = self.engine.explain_decision(decision.decision_id)
        assert explanation is not None
        assert explanation.decision_id == decision.decision_id
    
    def test_get_decision_history(self):
        """Test getting decision history."""
        self.engine.evaluate(DecisionType.TRANSACTION_APPROVAL, {"amount": 100})
        self.engine.evaluate(DecisionType.TRANSACTION_APPROVAL, {"amount": 200})
        
        history = self.engine.get_decision_history(limit=10)
        assert len(history) >= 2
    
    def test_log_audit(self):
        """Test logging audit."""
        decision = self.engine.evaluate(
            DecisionType.TRANSACTION_APPROVAL,
            {"amount": 100},
        )
        
        audit = self.engine.log_audit(
            decision_id=decision.decision_id,
            action="REVIEWED",
            user="admin",
        )
        
        assert audit is not None
        assert audit.decision_id == decision.decision_id


class TestModels:
    """Tests for model classes."""
    
    def test_decision_to_dict(self):
        """Test Decision serialization."""
        decision = Decision(
            decision_id="test-1",
            decision_type=DecisionType.TRANSACTION_APPROVAL,
            context={"amount": 100},
            outcome="APPROVED",
        )
        
        data = decision.to_dict()
        assert data["decision_id"] == "test-1"
        assert data["decision_type"] == "TRANSACTION_APPROVAL"
    
    def test_decision_type_values(self):
        """Test DecisionType enum."""
        assert DecisionType.FRAUD_APPROVAL.value == "FRAUD_APPROVAL"
        assert DecisionType.AML_ALERT.value == "AML_ALERT"
        assert len(DecisionType) > 0
    
    def test_decision_status_values(self):
        """Test DecisionStatus enum."""
        assert DecisionStatus.PENDING.value == "PENDING"
        assert DecisionStatus.APPROVED.value == "APPROVED"
    
    def test_decision_confidence_values(self):
        """Test DecisionConfidence enum."""
        assert DecisionConfidence.HIGH.value == "HIGH"
        assert DecisionConfidence.MEDIUM.value == "MEDIUM"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])