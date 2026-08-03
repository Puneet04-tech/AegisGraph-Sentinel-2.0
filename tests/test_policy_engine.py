"""
Unit tests for PolicyEngine in src/policy/policy_engine.py
"""

import pytest
from unittest.mock import MagicMock, patch
from dataclasses import dataclass


@dataclass
class FakePolicy:
    """Matches src/policy/policy_rule.PolicyRule interface."""
    name: str
    enabled: bool
    evaluator: callable
    description: str = ""


class FakeRegistry:
    def __init__(self, policies=None):
        self._policies = {p.name: p for p in (policies or [])}

    def get_policy(self, name):
        return self._policies.get(name)

    def list_policies(self):
        return list(self._policies.values())


class TestPolicyEngine:
    """Tests for PolicyEngine.evaluate and evaluate_all."""

    def _make_engine(self, policies=None):
        from src.policy.policy_engine import PolicyEngine
        registry = FakeRegistry(policies)
        return PolicyEngine(registry=registry)

    def test_evaluate_policy_not_found_returns_denied(self):
        """evaluate returns denied when policy does not exist."""
        engine = self._make_engine([])
        result = engine.evaluate("nonexistent", {})
        assert result.allowed is False
        assert "not found" in result.reason

    def test_evaluate_disabled_policy_returns_allowed(self):
        """evaluate returns allowed when policy is disabled."""
        policy = FakePolicy(name="test-policy", enabled=False, evaluator=lambda ctx: False)
        engine = self._make_engine([policy])
        result = engine.evaluate("test-policy", {})
        assert result.allowed is True
        assert "disabled" in result.reason

    def test_evaluate_calls_evaluator_and_returns_allowed(self):
        """evaluate calls the policy evaluator and returns its result."""
        policy = FakePolicy("allow-policy", enabled=True, evaluator=lambda ctx: True)
        engine = self._make_engine([policy])
        result = engine.evaluate("allow-policy", {"user": "alice"})
        assert result.allowed is True
        assert result.policy_name == "allow-policy"

    def test_evaluate_calls_evaluator_and_returns_denied(self):
        """evaluate calls the policy evaluator and returns denied result."""
        policy = FakePolicy("deny-policy", enabled=True, evaluator=lambda ctx: False)
        engine = self._make_engine([policy])
        result = engine.evaluate("deny-policy", {})
        assert result.allowed is False
        assert "denied by policy" in result.reason

    def test_evaluate_catches_evaluator_exception(self):
        """evaluate catches exceptions from the evaluator and returns denied."""
        def failing_evaluator(ctx):
            raise ValueError("eval failed")

        policy = FakePolicy("fail-policy", enabled=True, evaluator=failing_evaluator)
        engine = self._make_engine([policy])
        result = engine.evaluate("fail-policy", {})
        assert result.allowed is False
        assert "evaluation failed" in result.reason
        assert "eval failed" in result.reason

    def test_evaluate_all_empty_registry(self):
        """evaluate_all returns empty list when no policies registered."""
        engine = self._make_engine([])
        results = engine.evaluate_all({})
        assert results == []

    def test_evaluate_all_processes_enabled_policies(self):
        """evaluate_all calls evaluators for all enabled policies."""
        p1 = FakePolicy("enabled-1", enabled=True, evaluator=lambda ctx: True)
        p2 = FakePolicy("enabled-2", enabled=True, evaluator=lambda ctx: False)
        engine = self._make_engine([p1, p2])
        results = engine.evaluate_all({})
        assert len(results) == 2
        result_map = {r.policy_name: r for r in results}
        assert result_map["enabled-1"].allowed is True
        assert result_map["enabled-2"].allowed is False

    def test_evaluate_all_skips_disabled_policies(self):
        """evaluate_all skips disabled policies without calling evaluator."""
        disabled_calls = []

        def tracking_evaluator(ctx):
            disabled_calls.append(True)
            return True

        p1 = FakePolicy("enabled", enabled=True, evaluator=lambda ctx: True)
        p2 = FakePolicy("disabled", enabled=False, evaluator=tracking_evaluator)
        engine = self._make_engine([p1, p2])
        results = engine.evaluate_all({})
        assert len(results) == 2
        result_map = {r.policy_name: r for r in results}
        assert result_map["disabled"].allowed is True
        assert "disabled" in result_map["disabled"].reason
        assert disabled_calls == []

    def test_evaluate_all_handles_evaluator_exceptions(self):
        """evaluate_all handles exceptions from individual evaluators gracefully."""
        def bad_evaluator(ctx):
            raise RuntimeError("boom")

        p1 = FakePolicy("good", enabled=True, evaluator=lambda ctx: True)
        p2 = FakePolicy("bad", enabled=True, evaluator=bad_evaluator)
        engine = self._make_engine([p1, p2])
        results = engine.evaluate_all({})
        assert len(results) == 2
        result_map = {r.policy_name: r for r in results}
        assert result_map["good"].allowed is True
        assert result_map["bad"].allowed is False
        assert "evaluation failed" in result_map["bad"].reason

    def test_contains_returns_true_for_existing_policy(self):
        """contains returns True when the policy exists."""
        policy = FakePolicy(name="exists", enabled=True, evaluator=lambda ctx: True)
        engine = self._make_engine([policy])
        assert engine.contains("exists") is True

    def test_contains_returns_false_for_nonexistent_policy(self):
        """contains returns False when the policy does not exist."""
        engine = self._make_engine([])
        assert engine.contains("does-not-exist") is False

    def test_contains_does_not_call_evaluator(self):
        """contains checks existence without calling the evaluator."""
        calls = []

        def tracking_evaluator(ctx):
            calls.append(True)
            return True

        policy = FakePolicy(name="tracked", enabled=True, evaluator=tracking_evaluator)
        engine = self._make_engine([policy])
        engine.contains("tracked")
        assert calls == []

    def test_evaluate_passes_context_to_evaluator(self):
        """evaluate passes the context dict to the policy evaluator."""
        received_ctx = {}

        def capturing_evaluator(ctx):
            received_ctx.update(ctx)
            return True

        policy = FakePolicy("ctx-test", enabled=True, evaluator=capturing_evaluator)
        engine = self._make_engine([policy])
        engine.evaluate("ctx-test", {"role": "admin", "user": "bob"})
        assert received_ctx == {"role": "admin", "user": "bob"}
