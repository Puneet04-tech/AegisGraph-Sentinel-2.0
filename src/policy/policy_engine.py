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
        """Evaluate all registered policies against context using a single consistent snapshot."""
        snapshot = self.registry.list_policies()  # one lock acquisition, returns a copy
        results = []
        for policy in snapshot:
            if not policy.enabled:
                results.append(PolicyResult(True, policy.name, "policy disabled"))
                continue
            try:
                allowed = bool(policy.evaluator(context))
            except Exception as exc:
                results.append(PolicyResult(False, policy.name, f"policy evaluation failed: {exc}"))
                continue
            reason = "allowed" if allowed else "denied by policy"
            results.append(PolicyResult(allowed, policy.name, reason))
        return results
