"""Tests that TERMINATE policies override like DENY."""

from src.zero_trust.models import EvaluationContext, TrustLevel, TrustScore
from src.zero_trust.policy_engine import PolicyDecision, PolicyEnforcementEngine
from src.zero_trust.store import ZeroTrustStore


class TestTerminatePolicyDecision:
    def test_terminate_policy_returns_terminate_not_allow(self):
        store = ZeroTrustStore()
        store.policies.clear()
        engine = PolicyEnforcementEngine(store=store)
        engine.create_policy(
            name="Terminate Session",
            description="Hard terminate on match",
            conditions={"all_users": True},
            actions={"decision": PolicyDecision.TERMINATE},
            priority=50,
        )

        result = engine.evaluate_access(EvaluationContext(user_id="terminate-user"))
        assert result.decision == PolicyDecision.TERMINATE
        assert result.allowed is False

    def test_terminate_overrides_allow_policy(self):
        store = ZeroTrustStore()
        store.policies.clear()
        engine = PolicyEnforcementEngine(store=store)
        engine.create_policy(
            name="Allow All",
            description="Allow everyone",
            conditions={"all_users": True},
            actions={"decision": PolicyDecision.ALLOW},
            priority=100,
        )
        engine.create_policy(
            name="Terminate Compromised",
            description="Terminate compromised sessions",
            conditions={"all_users": True},
            actions={"decision": PolicyDecision.TERMINATE},
            priority=1,
        )

        trusted = TrustScore(score=0.95, level=TrustLevel.HIGHLY_TRUSTED)
        result = engine.evaluate_access(
            EvaluationContext(user_id="user-1"),
            trust_score=trusted,
        )
        assert result.decision == PolicyDecision.TERMINATE
        assert result.allowed is False

    def test_determine_final_decision_terminate_override(self):
        store = ZeroTrustStore()
        store.policies.clear()
        engine = PolicyEnforcementEngine(store=store)
        policy = engine.create_policy(
            name="Terminate",
            description="Terminate",
            conditions={"all_users": True},
            actions={"decision": PolicyDecision.TERMINATE},
            priority=1,
        )
        decision, allowed = engine._determine_final_decision(
            [policy.policy_id], [], TrustScore(score=0.9, level=TrustLevel.TRUSTED)
        )
        assert decision == PolicyDecision.TERMINATE
        assert allowed is False
