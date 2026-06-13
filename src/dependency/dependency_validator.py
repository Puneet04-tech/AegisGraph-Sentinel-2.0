"""Runtime dependency and service contract validator."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .dependency_registry import DependencyRegistry
from .validation_result import ValidationResult


class DependencyValidator:
    """Validates registered services against dependency rules and contracts."""

    def __init__(self, registry: DependencyRegistry) -> None:
        self.registry = registry

    def validate_dependencies(self, services: Any) -> list[ValidationResult]:
        service_map = self._service_map(services)
        results: list[ValidationResult] = []

        for rule in self.registry.list_rules():
            for dependency in rule.required_dependencies:
                if service_map.get(dependency) is None:
                    results.append(
                        ValidationResult(
                            valid=False,
                            service_name=rule.service_name,
                            reason=f"Missing required dependency: {dependency}",
                        )
                    )

        results.extend(self._detect_cycles())
        return results or [ValidationResult(True, "dependencies", "dependency validation passed")]

    def validate_contracts(self, services: Any) -> list[ValidationResult]:
        service_map = self._service_map(services)
        results: list[ValidationResult] = []

        for contract in self.registry.list_contracts():
            service = service_map.get(contract.service_name)
            if service is None:
                results.append(
                    ValidationResult(
                        valid=False,
                        service_name=contract.service_name,
                        reason="Service contract target is not registered",
                    )
                )
                continue
            for method_name in contract.required_methods:
                if not callable(getattr(service, method_name, None)):
                    results.append(
                        ValidationResult(
                            valid=False,
                            service_name=contract.service_name,
                            reason=f"Missing required method: {method_name}",
                        )
                    )

        return results or [ValidationResult(True, "contracts", "service contract validation passed")]

    def validate_all(self, services: Any) -> list[ValidationResult]:
        return self.validate_dependencies(services) + self.validate_contracts(services)

    def _service_map(self, services: Any) -> dict[str, Any]:
        if isinstance(services, Mapping):
            return dict(services)
        if hasattr(services, "list_services"):
            return services.list_services()
        return {}

    def _detect_cycles(self) -> list[ValidationResult]:
        graph = {
            rule.service_name: list(rule.required_dependencies)
            for rule in self.registry.list_rules()
        }
        visiting: set[str] = set()
        visited: set[str] = set()
        stack: list[str] = []
        cycles: list[ValidationResult] = []
        seen: set[tuple[str, ...]] = set()

        def visit(node: str) -> None:
            if node in visiting:
                start = stack.index(node)
                cycle = stack[start:] + [node]
                key = tuple(cycle)
                if key not in seen:
                    seen.add(key)
                    cycles.append(
                        ValidationResult(
                            valid=False,
                            service_name=node,
                            reason=f"Circular dependency detected: {' -> '.join(cycle)}",
                        )
                    )
                return
            if node in visited:
                return

            visiting.add(node)
            stack.append(node)
            for dependency in graph.get(node, []):
                if dependency in graph:
                    visit(dependency)
            stack.pop()
            visiting.remove(node)
            visited.add(node)

        for service_name in graph:
            visit(service_name)
        return cycles
