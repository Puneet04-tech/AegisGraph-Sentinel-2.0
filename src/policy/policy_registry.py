"""Thread-safe in-memory policy registry."""

from __future__ import annotations

from threading import RLock
from typing import Any, Dict, List, Optional

from .policy_rule import PolicyRule


class PolicyRegistry:
    """Stores runtime policies in memory only."""

    def __init__(self) -> None:
        self._policies: Dict[str, PolicyRule] = {}
        self._lock = RLock()
        self._authorization_engine: Any = None

    def set_authorization_engine(self, authorization_engine: Any) -> None:
        self._authorization_engine = authorization_engine

    def register_policy(self, policy: PolicyRule, authorization_context: Optional[Any] = None) -> PolicyRule:
        if not self._authorized(authorization_context):
            return policy
        with self._lock:
            self._policies[policy.name] = policy
            return policy

    def get_policy(self, name: str) -> Optional[PolicyRule]:
        with self._lock:
            return self._policies.get(name)

    def list_policies(self) -> List[PolicyRule]:
        with self._lock:
            return list(self._policies.values())

    def enable_policy(self, name: str, authorization_context: Optional[Any] = None) -> bool:
        if not self._authorized(authorization_context):
            return False
        with self._lock:
            policy = self._policies.get(name)
            if policy is None:
                return False
            policy.enabled = True
            return True

    def disable_policy(self, name: str, authorization_context: Optional[Any] = None) -> bool:
        if not self._authorized(authorization_context):
            return False
        with self._lock:
            policy = self._policies.get(name)
            if policy is None:
                return False
            policy.enabled = False
            return True

    def _authorized(self, authorization_context: Optional[Any]) -> bool:
        if authorization_context is None or self._authorization_engine is None:
            return True
        if isinstance(authorization_context, str):
            role = authorization_context
        elif isinstance(authorization_context, dict):
            role = str(authorization_context.get("role", ""))
        else:
            role = str(getattr(authorization_context, "role", ""))
        return self._authorization_engine.authorize(role, "policy.modify").allowed
