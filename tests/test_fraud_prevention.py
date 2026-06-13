"""Tests for Autonomous Fraud Prevention Network"""

import pytest

from src.fraud_prevention.models import PreventionPolicy, FraudPattern
from src.fraud_prevention.store import get_fraud_prevention_store, reset_fraud_prevention_store
from src.fraud_prevention.service import FraudPreventionService


class TestFraudPreventionModels:
    def test_create_policy(self):
        policy = PreventionPolicy(
            name="Block High Risk",
            description="Block high risk transactions",
            policy_type="BLOCK",
            action="BLOCK_TRANSACTION",
        )
        assert policy.name == "Block High Risk"
        assert policy.enabled

    def test_create_pattern(self):
        pattern = FraudPattern(
            name="Velocity Pattern",
            pattern_type="VELOCITY",
            indicators=["rapid_fire", "multiple_accounts"],
        )
        assert pattern.pattern_type == "VELOCITY"


class TestFraudPreventionStore:
    def setup_method(self):
        reset_fraud_prevention_store()
        self.store = get_fraud_prevention_store()

    def test_store_policy(self):
        policy = PreventionPolicy(name="Test", description="Test", policy_type="ALERT", action="ALERT")
        self.store.store_policy(policy)
        assert self.store.get_policy(policy.policy_id) is not None


class TestFraudPreventionService:
    def setup_method(self):
        reset_fraud_prevention_store()
        self.service = FraudPreventionService()

    def test_create_policy(self):
        policy = self.service.create_policy("Test Policy", "Test", "BLOCK", "BLOCK_TRANSACTION")
        assert policy.policy_id is not None

    def test_learn_pattern(self):
        pattern = self.service.learn_pattern("New Pattern", "BEHAVIORAL", ["unusual_location", "time_anomaly"])
        assert pattern.pattern_id is not None

    def test_calculate_risk(self):
        score = self.service.calculate_risk("entity-001", ["high_amount", "new_device"])
        assert score.score_id is not None

    def test_create_block_rule(self):
        pattern = self.service.learn_pattern("Test", "TYPE", [])
        rule = self.service.create_block_rule("High Risk Block", pattern.pattern_id, 0.9)
        assert rule.rule_id is not None

    def test_prevent(self):
        event = self.service.prevent("FRAUD_ATTEMPT", "entity-002", "BLOCKED")
        assert event.event_id is not None
        assert event.outcome == "PREVENTED"

    def test_get_metrics(self):
        self.service.create_policy("Test", "Test", "ALERT", "ALERT")
        metrics = self.service.get_metrics()
        assert metrics.policies_active >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
