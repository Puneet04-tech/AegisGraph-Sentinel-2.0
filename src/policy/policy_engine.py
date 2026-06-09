"""Minimal runtime policy evaluator."""

from __future__ import annotations

from typing import Any, Dict, List

from .policy_registry import PolicyRegistry
from .policy_result import PolicyResult


class PolicyEngine:
    """Evaluates registered policies against runtime context."""

    def __init__(self, registry: PolicyRegistry) -> None:
        self.registry = registry

    def evaluate(self, policy_name: str, context: Dict[str, Any]) -> PolicyResult:
        policy = self.registry.get_policy(policy_name)
        if policy is None:
            return PolicyResult(False, policy_name, "policy not found")
        if not policy.enabled:
            return PolicyResult(True, policy.name, "policy disabled")
        try:
            allowed = bool(policy.evaluator(context))
        except Exception as exc:
            return PolicyResult(False, policy.name, f"policy evaluation failed: {exc}")
        reason = "allowed" if allowed else "denied by policy"
        return PolicyResult(allowed, policy.name, reason)

    def evaluate_all(self, context: Dict[str, Any]) -> List[PolicyResult]:
        return [self.evaluate(policy.name, context) for policy in self.registry.list_policies()]
