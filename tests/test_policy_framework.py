"""Focused tests for the in-memory runtime policy framework."""

from __future__ import annotations

import asyncio

from src.configuration import ConfigRegistry, ConfigReloadManager
from src.policy import (
    PolicyEngine,
    PolicyRegistry,
    PolicyRule,
    max_recovery_attempts_guardrail,
    resource_throttled_guardrail,
)
from src.runtime import RecoveryManager, RuntimeHealthMonitor, RuntimeState
from src.runtime.resources import ResourceLimits, RuntimeResourceManager


def _registry_with(policy: PolicyRule) -> PolicyRegistry:
    registry = PolicyRegistry()
    registry.register_policy(policy)
    return registry


def test_policy_registration():
    registry = PolicyRegistry()
    policy = PolicyRule("allow", "allows requests", True, lambda context: True)

    registered = registry.register_policy(policy)

    assert registered is policy
    assert registry.get_policy("allow") is policy
    assert registry.list_policies() == [policy]


def test_policy_enable_disable():
    registry = _registry_with(PolicyRule("toggle", "toggle policy", True, lambda context: True))

    assert registry.disable_policy("toggle") is True
    assert registry.get_policy("toggle").enabled is False
    assert registry.enable_policy("toggle") is True
    assert registry.get_policy("toggle").enabled is True
    assert registry.disable_policy("missing") is False


def test_single_policy_evaluation():
    engine = PolicyEngine(
        _registry_with(PolicyRule("needs_flag", "requires allowed flag", True, lambda context: context["allowed"]))
    )

    result = engine.evaluate("needs_flag", {"allowed": True})

    assert result.allowed is True
    assert result.policy_name == "needs_flag"
    assert result.reason == "allowed"


def test_evaluate_all():
    registry = PolicyRegistry()
    registry.register_policy(PolicyRule("allow", "allow", True, lambda context: True))
    registry.register_policy(PolicyRule("deny", "deny", True, lambda context: False))
    engine = PolicyEngine(registry)

    results = engine.evaluate_all({})

    assert [result.policy_name for result in results] == ["allow", "deny"]
    assert [result.allowed for result in results] == [True, False]


def test_policy_failure_handling():
    def broken(context):
        raise RuntimeError("boom")

    engine = PolicyEngine(_registry_with(PolicyRule("broken", "raises", True, broken)))

    result = engine.evaluate("broken", {})

    assert result.allowed is False
    assert result.policy_name == "broken"
    assert "policy evaluation failed: boom" == result.reason


def test_recovery_guardrail():
    assert max_recovery_attempts_guardrail({"restart_attempts": 0, "max_attempts": 1}) is True
    assert max_recovery_attempts_guardrail({"restart_attempts": 1, "max_attempts": 1}) is False


def test_recovery_manager_evaluates_guardrail_before_recovery():
    async def _run():
        state = RuntimeState()
        state.health_monitor.register_service("svc")
        state.health_monitor.mark_failed("svc", error="failed")
        recovery = RecoveryManager(state.health_monitor)
        state.set_recovery_manager(recovery)
        calls = []
        recovery.register_recovery_callback("svc", lambda: calls.append("called"), max_attempts=0)

        assert await recovery.handle_failure("svc") is False
        assert calls == []

    asyncio.run(_run())


def test_throttling_guardrail():
    assert resource_throttled_guardrail({"resource_throttled": False, "backpressure_state": "healthy"}) is True
    assert resource_throttled_guardrail({"resource_throttled": True, "backpressure_state": "healthy"}) is False
    assert resource_throttled_guardrail({"resource_throttled": False, "backpressure_state": "throttled"}) is False


def test_resource_manager_evaluates_throttling_guardrail_before_events():
    state = RuntimeState(resource_manager=RuntimeResourceManager(ResourceLimits(max_event_queue_size=1)))
    state.resource_manager.update_queue_size(1, 1)

    assert state.resource_manager.can_accept_event() is False
    assert state.resource_manager.get_resource_metrics()["event_rate"] == 0


def test_config_reload_guardrail_denies_reload():
    registry = ConfigRegistry()
    registry.register("limit", 1, expected_type=int)
    policy_registry = _registry_with(
        PolicyRule("config_reload_allowed", "deny reload", True, lambda context: False)
    )
    manager = ConfigReloadManager(registry, policy_engine=PolicyEngine(policy_registry))

    result = manager.reload({"limit": 2})

    assert result.valid is False
    assert registry.get("limit") == 1
    assert "policy denied reload: denied by policy" in result.errors


def test_runtime_integration_metrics():
    state = RuntimeState()

    metrics = state.get_metrics()

    assert state.get_service("policy_registry") is state.policy_registry
    assert state.get_service("policy_engine") is state.policy_engine
    assert metrics["policies"]["count"] == 4
    assert metrics["policies"]["enabled"] == 4
    assert "max_recovery_attempts" in metrics["policies"]["names"]
