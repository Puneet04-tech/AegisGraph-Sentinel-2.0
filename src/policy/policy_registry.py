"""Thread-safe in-memory policy registry."""

from __future__ import annotations

from threading import RLock
from typing import Dict, List, Optional

from .policy_rule import PolicyRule


class PolicyRegistry:
    """Stores runtime policies in memory only."""

    def __init__(self) -> None:
        self._policies: Dict[str, PolicyRule] = {}
        self._lock = RLock()

    def register_policy(self, policy: PolicyRule) -> PolicyRule:
        with self._lock:
            self._policies[policy.name] = policy
            return policy

    def get_policy(self, name: str) -> Optional[PolicyRule]:
        with self._lock:
            return self._policies.get(name)

    def list_policies(self) -> List[PolicyRule]:
        with self._lock:
            return list(self._policies.values())

    def enable_policy(self, name: str) -> bool:
        with self._lock:
            policy = self._policies.get(name)
            if policy is None:
                return False
            policy.enabled = True
            return True

    def disable_policy(self, name: str) -> bool:
        with self._lock:
            policy = self._policies.get(name)
            if policy is None:
                return False
            policy.enabled = False
            return True
