"""
Tests for Adaptive Risk Control Platform.
"""

import pytest

from src.adaptive_risk_control import (
    # Models
    RiskLevel,
    DecisionType,
    MitigationAction,
    LearningFeedbackType,
    RiskProfile,
    TransactionAssessment,
    ControlRule,
    AdaptivePolicy,
    LearningFeedback,
    # Store
    get_adaptive_risk_store,
    reset_store,
    # Engines
    get_risk_engine,
    get_prevention_engine,
    get_policy_engine,
    get_control_manager,
    get_mitigation_engine,
    get_recommendation_engine,
    get_learning_engine,
    # Service
    get_prevention_service,
)


class TestModels:
    """Test data models."""

    def test_risk_profile_creation(self):
        """Test risk profile model."""
        profile = RiskProfile(
            profile_id="profile-1",
            entity_id="entity-1",
            entity_type="user",
            risk_score=0.5,
            risk_level=RiskLevel.MEDIUM,
            trust_score=0.5,
        )

        assert profile.profile_id == "profile-1"
        assert profile.risk_score == 0.5
        assert profile.risk_level == RiskLevel.MEDIUM

    def test_transaction_assessment(self):
        """Test transaction assessment model."""
        assessment = TransactionAssessment(
            assessment_id="assess-1",
            transaction_id="txn-1",
            entity_id="entity-1",
            risk_score=0.7,
            risk_level=RiskLevel.HIGH,
            decision=DecisionType.REVIEW,
            confidence=0.8,
            risk_factors=["high_velocity"],
            indicators=["vpn_detected"],
        )

        assert assessment.risk_score == 0.7
        assert assessment.decision == DecisionType.REVIEW


class TestAdaptiveRiskStore:
    """Test adaptive risk store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_store()

    def test_profile_storage(self):
        """Test storing and retrieving profiles."""
        store = get_adaptive_risk_store()

        profile = RiskProfile(
            profile_id="profile-1",
            entity_id="entity-1",
            entity_type="user",
            risk_score=0.5,
            risk_level=RiskLevel.MEDIUM,
            trust_score=0.5,
        )

        store.store_profile(profile)
        retrieved = store.get_profile("profile-1")

        assert retrieved is not None
        assert retrieved.profile_id == "profile-1"

    def test_profile_by_entity(self):
        """Test getting profile by entity ID."""
        store = get_adaptive_risk_store()

        profile = RiskProfile(
            profile_id="profile-1",
            entity_id="entity-1",
            entity_type="user",
            risk_score=0.5,
            risk_level=RiskLevel.MEDIUM,
            trust_score=0.5,
        )

        store.store_profile(profile)
        retrieved = store.get_profile_by_entity("entity-1")

        assert retrieved is not None
        assert retrieved.entity_id == "entity-1"

    def test_assessment_storage(self):
        """Test storing assessments."""
        store = get_adaptive_risk_store()

        assessment = TransactionAssessment(
            assessment_id="assess-1",
            transaction_id="txn-1",
            entity_id="entity-1",
            risk_score=0.7,
            risk_level=RiskLevel.HIGH,
            decision=DecisionType.REVIEW,
            confidence=0.8,
            risk_factors=[],
            indicators=[],
        )

        store.store_assessment(assessment)
        retrieved = store.get_assessment("assess-1")

        assert retrieved is not None
        assert retrieved.assessment_id == "assess-1"


class TestAdaptiveRiskEngine:
    """Test adaptive risk engine."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_risk_evaluation(self):
        """Test risk evaluation."""
        import asyncio

        engine = get_risk_engine()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run_test():
            assessment = await engine.evaluate_risk(
                entity_id="entity-1",
                transaction_data={
                    "transaction_id": "txn-1",
                    "amount": 5000,
                    "velocity": 3,
                    "device_trusted": True,
                },
            )
            return assessment

        assessment = loop.run_until_complete(run_test())
        loop.close()

        assert assessment.assessment_id is not None
        assert assessment.risk_score >= 0
        assert assessment.risk_score <= 1

    def test_risk_level_determination(self):
        """Test risk level determination."""
        engine = get_risk_engine()

        assert engine._determine_risk_level(0.95) == RiskLevel.CRITICAL
        assert engine._determine_risk_level(0.75) == RiskLevel.HIGH
        assert engine._determine_risk_level(0.55) == RiskLevel.MEDIUM
        assert engine._determine_risk_level(0.35) == RiskLevel.LOW
        assert engine._determine_risk_level(0.15) == RiskLevel.MINIMAL


class TestFraudPreventionEngine:
    """Test fraud prevention engine."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_prevent_fraud_block(self):
        """Test fraud prevention with block decision."""
        import asyncio

        engine = get_prevention_engine()

        assessment = TransactionAssessment(
            assessment_id="assess-1",
            transaction_id="txn-1",
            entity_id="entity-1",
            risk_score=0.95,
            risk_level=RiskLevel.CRITICAL,
            decision=DecisionType.BLOCK,
            confidence=0.9,
            risk_factors=["high_risk"],
            indicators=["fraud_indicators"],
        )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run_test():
            result = await engine.prevent_fraud(assessment)
            return result

        result = loop.run_until_complete(run_test())
        loop.close()

        assert result["prevented"] is True
        assert "block" in str(result["actions_taken"]).lower()

    def test_record_fraud_attempt(self):
        """Test recording fraud attempt."""
        import asyncio

        engine = get_prevention_engine()

        assessment = TransactionAssessment(
            assessment_id="assess-1",
            transaction_id="txn-1",
            entity_id="entity-1",
            risk_score=0.8,
            risk_level=RiskLevel.HIGH,
            decision=DecisionType.BLOCK,
            confidence=0.8,
            risk_factors=[],
            indicators=["vpn_detected"],
        )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run_test():
            attempt = await engine.record_fraud_attempt(
                entity_id="entity-1",
                assessment=assessment,
            )
            return attempt

        attempt = loop.run_until_complete(run_test())
        loop.close()

        assert attempt.attempt_id is not None
        assert attempt.entity_id == "entity-1"
        assert attempt.risk_score == 0.8


class TestPolicyDecisionEngine:
    """Test policy decision engine."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_create_policy(self):
        """Test creating a policy."""
        import asyncio

        engine = get_policy_engine()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run_test():
            policy = await engine.create_policy(
                name="High Risk Policy",
                description="Policy for high risk transactions",
                risk_threshold=0.7,
                control_actions=[MitigationAction.BLOCK, MitigationAction.NOTIFY],
            )
            return policy

        policy = loop.run_until_complete(run_test())
        loop.close()

        assert policy.policy_id is not None
        assert policy.name == "High Risk Policy"
        assert policy.risk_threshold == 0.7

    def test_create_control_rule(self):
        """Test creating a control rule."""
        import asyncio

        engine = get_policy_engine()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run_test():
            rule = await engine.create_control_rule(
                name="Velocity Rule",
                rule_type="velocity",
                conditions={"velocity_threshold": 5},
                action=MitigationAction.BLOCK,
                risk_threshold=0.6,
            )
            return rule

        rule = loop.run_until_complete(run_test())
        loop.close()

        assert rule.rule_id is not None
        assert rule.name == "Velocity Rule"
        assert rule.action == MitigationAction.BLOCK


class TestDynamicControlManager:
    """Test dynamic control manager."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_activate_control(self):
        """Test activating a control."""
        import asyncio

        manager = get_control_manager()

        rule = ControlRule(
            rule_id="rule-1",
            name="Test Rule",
            rule_type="test",
            conditions={},
            action=MitigationAction.BLOCK,
            risk_threshold=0.7,
        )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run_test():
            result = await manager.activate_control(rule)
            return result

        result = loop.run_until_complete(run_test())
        loop.close()

        assert result["status"] == "active"
        assert result["control_id"] == "rule-1"

    def test_deactivate_control(self):
        """Test deactivating a control."""
        import asyncio

        manager = get_control_manager()

        rule = ControlRule(
            rule_id="rule-1",
            name="Test Rule",
            rule_type="test",
            conditions={},
            action=MitigationAction.BLOCK,
            risk_threshold=0.7,
        )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # First activate
        async def activate():
            await manager.activate_control(rule)

        loop.run_until_complete(activate())

        # Then deactivate
        async def deactivate():
            result = await manager.deactivate_control("rule-1", "Test deactivation")
            return result

        result = loop.run_until_complete(deactivate())
        loop.close()

        assert result["status"] == "inactive"


class TestRealTimeMitigationEngine:
    """Test real-time mitigation engine."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_execute_mitigation(self):
        """Test executing mitigation action."""
        import asyncio

        engine = get_mitigation_engine()

        assessment = TransactionAssessment(
            assessment_id="assess-1",
            transaction_id="txn-1",
            entity_id="entity-1",
            risk_score=0.9,
            risk_level=RiskLevel.CRITICAL,
            decision=DecisionType.BLOCK,
            confidence=0.9,
            risk_factors=[],
            indicators=[],
        )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run_test():
            result = await engine.execute_mitigation(assessment, MitigationAction.BLOCK)
            return result

        result = loop.run_until_complete(run_test())
        loop.close()

        assert result["action"] == "block"
        assert result["status"] == "executed"


class TestPolicyRecommendationEngine:
    """Test policy recommendation engine."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_generate_recommendations(self):
        """Test generating recommendations."""
        import asyncio

        engine = get_recommendation_engine()

        assessments = [
            TransactionAssessment(
                assessment_id=f"assess-{i}",
                transaction_id=f"txn-{i}",
                entity_id="entity-1",
                risk_score=0.7 + i * 0.05,
                risk_level=RiskLevel.HIGH,
                decision=DecisionType.REVIEW,
                confidence=0.8,
                risk_factors=["velocity"],
                indicators=[],
            )
            for i in range(5)
        ]

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run_test():
            recommendations = await engine.generate_recommendations(
                entity_id="entity-1",
                recent_assessments=assessments,
            )
            return recommendations

        recommendations = loop.run_until_complete(run_test())
        loop.close()

        assert isinstance(recommendations, list)


class TestAdaptiveLearningEngine:
    """Test adaptive learning engine."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_process_feedback(self):
        """Test processing learning feedback."""
        import asyncio

        engine = get_learning_engine()

        feedback = LearningFeedback(
            feedback_id="feedback-1",
            entity_id="entity-1",
            transaction_id="txn-1",
            feedback_type=LearningFeedbackType.POSITIVE,
            risk_score_predicted=0.7,
            risk_score_actual=0.65,
            features={},
            model_version="1.0.0",
        )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run_test():
            result = await engine.process_feedback(feedback)
            return result

        result = loop.run_until_complete(run_test())
        loop.close()

        assert result["processed"] is True
        assert result["feedback_id"] == "feedback-1"

    def test_get_learning_stats(self):
        """Test getting learning stats."""
        import asyncio

        engine = get_learning_engine()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run_test():
            stats = await engine.get_learning_stats()
            return stats

        stats = loop.run_until_complete(run_test())
        loop.close()

        assert "total_feedback" in stats
        assert "model_version" in stats


class TestAdaptiveRiskControlService:
    """Test main adaptive risk control service."""

    def setup_method(self):
        """Reset store."""
        reset_store()

    def test_evaluate_risk(self):
        """Test risk evaluation via service."""
        import asyncio

        service = get_prevention_service()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run_test():
            result = await service.evaluate_risk(
                entity_id="entity-1",
                transaction_data={
                    "transaction_id": "txn-1",
                    "amount": 5000,
                    "velocity": 3,
                },
            )
            return result

        result = loop.run_until_complete(run_test())
        loop.close()

        assert "assessment_id" in result
        assert "risk_score" in result
        assert "decision" in result

    def test_get_dashboard(self):
        """Test getting dashboard."""
        import asyncio

        service = get_prevention_service()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run_test():
            dashboard = await service.get_dashboard()
            return dashboard

        dashboard = loop.run_until_complete(run_test())
        loop.close()

        assert "risk_stats" in dashboard
        assert "active_controls" in dashboard

    def test_get_policies(self):
        """Test getting policies."""
        import asyncio

        service = get_prevention_service()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run_test():
            policies = await service.get_policies()
            return policies

        policies = loop.run_until_complete(run_test())
        loop.close()

        assert isinstance(policies, list)


class TestControlRules:
    """Test control rule functionality."""

    def test_control_rule_creation(self):
        """Test creating a control rule."""
        rule = ControlRule(
            rule_id="rule-1",
            name="Test Rule",
            rule_type="test",
            conditions={"test_condition": True},
            action=MitigationAction.BLOCK,
            risk_threshold=0.7,
            priority=100,
        )

        assert rule.rule_id == "rule-1"
        assert rule.action == MitigationAction.BLOCK
        assert rule.is_active is True

    def test_adaptive_policy_creation(self):
        """Test creating an adaptive policy."""
        policy = AdaptivePolicy(
            policy_id="policy-1",
            name="Test Policy",
            description="Test policy description",
            risk_threshold=0.8,
            control_actions=[MitigationAction.BLOCK, MitigationAction.FLAG],
            conditions={"test": True},
        )

        assert policy.policy_id == "policy-1"
        assert len(policy.control_actions) == 2
        assert policy.is_active is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])