"""Thread-safe in-memory dependency metadata registry."""

from __future__ import annotations

import threading
from typing import Optional

from .dependency_rule import DependencyRule
from .service_contract import ServiceContract


class DependencyRegistry:
    """Stores dependency rules and service contracts in memory only."""

    def __init__(self) -> None:
        self._rules: dict[str, DependencyRule] = {}
        self._contracts: dict[str, ServiceContract] = {}
        self._lock = threading.Lock()

    def register_dependency_rule(self, rule: DependencyRule) -> DependencyRule:
        with self._lock:
            self._rules[rule.service_name] = rule
        return rule

    def register_service_contract(self, contract: ServiceContract) -> ServiceContract:
        with self._lock:
            self._contracts[contract.service_name] = contract
        return contract

    def get_dependency_rule(self, service_name: str) -> Optional[DependencyRule]:
        with self._lock:
            return self._rules.get(service_name)

    def get_service_contract(self, service_name: str) -> Optional[ServiceContract]:
        with self._lock:
            return self._contracts.get(service_name)

    def list_rules(self) -> list[DependencyRule]:
        with self._lock:
            return list(self._rules.values())

    def list_contracts(self) -> list[ServiceContract]:
        with self._lock:
            return list(self._contracts.values())
