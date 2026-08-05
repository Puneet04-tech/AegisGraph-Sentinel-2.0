"""Tests for the adaptive_auth policy conditions violation path.

`evaluate_policy` previously returned ALLOW when a policy's conditions were
not met, so restrictions such as allowed_hours and allowed_ip_ranges were
silently ignored. A conditions violation must deny via action_on_violation,
mirroring the trust/risk/auth-method checks.
"""

import pytest
from datetime import datetime, timezone

from src.adaptive_auth.models import (
    AuthorizationPolicy,
    ChallengeType,
    PolicyAction,
    RiskLevel,
    TrustLevel,
)
from src.adaptive_auth.policy_engine import PolicyEvaluationContext, PolicyEvaluator
from src.adaptive_auth.store import get_adaptive_auth_store, reset_store


def make_policy(
    action_on_violation: PolicyAction = PolicyAction.DENY,
    conditions=None,
    step_up_required: bool = False,
    step_up_challenge_types=None,
) -> AuthorizationPolicy:
    return AuthorizationPolicy(
        policy_id="policy-1",
        name="Conditions Policy",
        description="A policy with conditions",
        resource_pattern=r"/api/v1/transfers.*",
        required_trust_level=TrustLevel.LOW,
        required_risk_level=RiskLevel.HIGH,
        action_on_violation=action_on_violation,
        conditions=conditions or {},
        step_up_required=step_up_required,
        step_up_challenge_types=step_up_challenge_types or [],
    )


def make_context(ip_address: str = "192.168.1.50", hour: int = 3) -> PolicyEvaluationContext:
    store = get_adaptive_auth_store()
    session = store.create_session(
        user_id="user1",
        ip_address=ip_address,
        user_agent="TestAgent/1.0",
    )
    return PolicyEvaluationContext(
        session=session,
        resource="/api/v1/transfers/123",
        action="create",
        risk_score=None,
        trust_level=TrustLevel.HIGH,
        user_id="user1",
        ip_address=ip_address,
        user_agent="TestAgent/1.0",
        timestamp=datetime(2026, 1, 15, hour, 0, 0, tzinfo=timezone.utc),
    )


@pytest.fixture
def evaluator() -> PolicyEvaluator:
    reset_store()
    return PolicyEvaluator(get_adaptive_auth_store())


class TestPolicyConditionsDeny:
    def test_allowed_hours_outside_window_denies(self, evaluator):
        policy = make_policy(conditions={"allowed_hours": [9, 17]})
        decision = evaluator.evaluate_policy(policy, make_context(hour=3))
        assert decision.allowed is False
        assert decision.action == PolicyAction.DENY
        assert decision.denied_reason == "Policy conditions not met"

    def test_allowed_hours_inside_window_allows(self, evaluator):
        policy = make_policy(conditions={"allowed_hours": [9, 17]})
        decision = evaluator.evaluate_policy(policy, make_context(hour=12))
        assert decision.allowed is True
        assert decision.action == PolicyAction.ALLOW

    def test_allowed_ip_ranges_outside_range_denies(self, evaluator):
        policy = make_policy(conditions={"allowed_ip_ranges": ["10.0.0.0/8"]})
        decision = evaluator.evaluate_policy(policy, make_context(ip_address="192.168.1.50"))
        assert decision.allowed is False
        assert decision.action == PolicyAction.DENY
        assert decision.denied_reason == "Policy conditions not met"

    def test_allowed_ip_ranges_inside_range_allows(self, evaluator):
        policy = make_policy(conditions={"allowed_ip_ranges": ["192.168.0.0/16"]})
        decision = evaluator.evaluate_policy(policy, make_context(ip_address="192.168.1.50"))
        assert decision.allowed is True
        assert decision.action == PolicyAction.ALLOW

    def test_step_up_action_on_violation_applied(self, evaluator):
        policy = make_policy(
            action_on_violation=PolicyAction.STEP_UP,
            step_up_required=True,
            step_up_challenge_types=[ChallengeType.TOTP],
            conditions={"allowed_hours": [9, 17]},
        )
        decision = evaluator.evaluate_policy(policy, make_context(hour=3))
        assert decision.allowed is False
        assert decision.action == PolicyAction.STEP_UP
        assert decision.requires_step_up is True
        assert decision.step_up_challenge_types == ["totp"]
        assert decision.denied_reason == "Policy conditions not met"
