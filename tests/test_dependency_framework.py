import asyncio

from src.dependency import (
    DependencyRegistry,
    DependencyRule,
    DependencyValidator,
    ServiceContract,
)
from src.runtime import LifecycleManager, RuntimeState


class StartableService:
    def start(self):
        return None


class PlainService:
    pass


def test_dependency_registration():
    registry = DependencyRegistry()
    rule = DependencyRule(
        service_name="fraud_service",
        required_dependencies=["graph_store"],
        optional_dependencies=["cache"],
    )

    assert registry.register_dependency_rule(rule) is rule
    assert registry.get_dependency_rule("fraud_service") == rule
    assert registry.list_rules() == [rule]


def test_contract_registration():
    registry = DependencyRegistry()
    contract = ServiceContract(service_name="fraud_service", required_methods=["start"])

    assert registry.register_service_contract(contract) is contract
    assert registry.get_service_contract("fraud_service") == contract


def test_missing_dependency_detection():
    registry = DependencyRegistry()
    registry.register_dependency_rule(
        DependencyRule(service_name="fraud_service", required_dependencies=["graph_store"])
    )
    validator = DependencyValidator(registry)

    results = validator.validate_dependencies({"fraud_service": object()})

    assert any(not result.valid for result in results)
    assert any("graph_store" in result.reason for result in results)


def test_missing_method_detection():
    registry = DependencyRegistry()
    registry.register_service_contract(ServiceContract(service_name="fraud_service", required_methods=["start"]))
    validator = DependencyValidator(registry)

    results = validator.validate_contracts({"fraud_service": PlainService()})

    assert any(not result.valid for result in results)
    assert any("start" in result.reason for result in results)


def test_circular_dependency_detection():
    registry = DependencyRegistry()
    registry.register_dependency_rule(DependencyRule(service_name="a", required_dependencies=["b"]))
    registry.register_dependency_rule(DependencyRule(service_name="b", required_dependencies=["c"]))
    registry.register_dependency_rule(DependencyRule(service_name="c", required_dependencies=["a"]))
    validator = DependencyValidator(registry)

    results = validator.validate_dependencies(
        {"a": object(), "b": object(), "c": object()}
    )

    assert any(not result.valid and "Circular dependency" in result.reason for result in results)


def test_successful_validation():
    registry = DependencyRegistry()
    registry.register_dependency_rule(DependencyRule(service_name="fraud_service", required_dependencies=["cache"]))
    registry.register_service_contract(ServiceContract(service_name="fraud_service", required_methods=["start"]))
    validator = DependencyValidator(registry)

    results = validator.validate_all(
        {"fraud_service": StartableService(), "cache": object()}
    )

    assert results
    assert all(result.valid for result in results)


def test_runtime_integration_metrics():
    async def _run():
        runtime_state = RuntimeState()
        runtime_state.dependency_registry.register_dependency_rule(
            DependencyRule(service_name="api", required_dependencies=["missing"])
        )
        lifecycle = LifecycleManager(runtime_state)

        await lifecycle.startup()

        metrics = runtime_state.get_metrics()
        assert runtime_state.get_service("dependency_registry") is runtime_state.dependency_registry
        assert runtime_state.get_service("dependency_validator") is runtime_state.dependency_validator
        assert metrics["dependencies"]["rule_count"] == 1
        assert metrics["dependencies"]["last_valid"] is False
        assert metrics["dependencies"]["failure_count"] == 1
        assert metrics["dependencies"]["failures"][0]["service_name"] == "api"
        assert runtime_state.started is True
        await lifecycle.shutdown()

    asyncio.run(_run())
