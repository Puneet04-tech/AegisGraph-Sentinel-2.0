"""Tests for Autonomous Fraud Prevention"""
import pytest
from src.fraud_prevention.models import FraudAlert, PreventionRule
from src.fraud_prevention.store import get_fraud_prevention_store
from src.fraud_prevention.service import FraudPreventionService


class TestFraudPreventionModels:
    def test_create_alert(self):
        a = FraudAlert(transaction_id="TX123", risk_score=0.85, reason="High risk")
        assert a.risk_score == 0.85

    def test_create_rule(self):
        r = PreventionRule(name="Block High Risk", condition={"score": 0.9}, action="BLOCK")
        assert r.action == "BLOCK"


class TestFraudPreventionStore:
    def setup_method(self):
        self.store = get_fraud_prevention_store()

    def test_store_alert(self):
        a = FraudAlert(transaction_id="TX123", risk_score=0.8, reason="Test")
        self.store.store_alert(a)
        assert self.store.get_alert(a.alert_id) is not None


class TestFraudPreventionService:
    def setup_method(self):
        self.service = FraudPreventionService()

    def test_create_alert(self):
        a = self.service.create_alert("TX123", 0.85, "High risk")
        assert a.alert_id is not None

    def test_create_rule(self):
        r = self.service.create_rule("Block High Risk", {"score": 0.9}, "BLOCK")
        assert r.rule_id is not None

    def test_get_metrics(self):
        self.service.create_alert("TX123", 0.8, "Test")
        m = self.service.get_metrics()
        assert m.total_alerts >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
