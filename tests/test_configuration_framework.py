"""Focused tests for runtime configuration governance."""

from __future__ import annotations

from types import MappingProxyType

import pytest

from src.audit import AuditLogger, AuditStore
from src.configuration import ConfigRegistry, ConfigReloadManager, ConfigSnapshot, ConfigValidator
from src.runtime import RecoveryManager, RuntimeHealthMonitor, RuntimeState
from src.runtime.resources import RuntimeResourceManager


def test_config_registration_and_retrieval():
    registry = ConfigRegistry()

    entry = registry.register("max_tasks", 10, default=5, required=True, expected_type=int)

    assert entry.name == "max_tasks"
    assert registry.get("max_tasks") == 10
    assert registry.exists("max_tasks") is True
    assert [config.name for config in registry.list_configs()] == ["max_tasks"]


def test_config_updates():
    registry = ConfigRegistry()
    registry.register("mode", "safe", expected_type=str)

    updated = registry.update("mode", "active")

    assert updated.value == "active"
    assert registry.get("mode") == "active"


def test_required_field_validation():
    registry = ConfigRegistry()
    entry = registry.register("api_key", None, required=True, expected_type=str)

    result = ConfigValidator.validate(entry)

    assert result.valid is False
    assert "api_key is required" in result.errors


def test_type_validation():
    registry = ConfigRegistry()
    entry = registry.register("threshold", "high", expected_type=float)

    result = ConfigValidator.validate(entry)

    assert result.valid is False
    assert "threshold must be float; got str" in result.errors


def test_custom_validator_support():
    registry = ConfigRegistry()
    valid_entry = registry.register("ratio", 0.5, expected_type=float, validator=lambda value: 0 <= value <= 1)
    invalid_entry = registry.register("bad_ratio", 2.0, expected_type=float, validator=lambda value: 0 <= value <= 1)

    assert ConfigValidator.validate(valid_entry).valid is True
    result = ConfigValidator.validate(invalid_entry)
    assert result.valid is False
    assert "bad_ratio failed custom validation" in result.errors


def test_snapshot_generation_is_immutable():
    registry = ConfigRegistry()
    registry.register("mode", "safe", expected_type=str)

    snapshot = ConfigSnapshot.capture(registry)
    registry.update("mode", "active")

    assert isinstance(snapshot.values, MappingProxyType)
    assert snapshot.values["mode"] == "safe"
    assert snapshot.timestamp.endswith("Z")
    with pytest.raises(TypeError):
        snapshot.values["mode"] = "changed"


def test_successful_reload_records_audit_event():
    registry = ConfigRegistry()
    registry.register("limit", 10, expected_type=int, validator=lambda value: value > 0)
    store = AuditStore()
    audit_logger = AuditLogger(store)
    manager = ConfigReloadManager(registry, audit_logger=audit_logger.log_audit_event)

    result = manager.reload({"limit": 20})

    assert result.valid is True
    assert registry.get("limit") == 20
    event_types = [record["event"].event_type for record in store.get_events()]
    assert "config_reload_success" in event_types


def test_rejected_reload_preserves_previous_value_and_records_audit():
    registry = ConfigRegistry()
    registry.register("limit", 10, expected_type=int, validator=lambda value: value > 0)
    store = AuditStore()
    audit_logger = AuditLogger(store)
    manager = ConfigReloadManager(registry, audit_logger=audit_logger.log_audit_event)

    result = manager.reload({"limit": -1})

    assert result.valid is False
    assert registry.get("limit") == 10
    event_types = [record["event"].event_type for record in store.get_events()]
    assert "config_validation_failed" in event_types
    assert "config_reload_failed" in event_types


def test_rejected_reload_for_unregistered_key():
    registry = ConfigRegistry()
    manager = ConfigReloadManager(registry)

    result = manager.reload({"missing": "value"})

    assert result.valid is False
    assert "missing is not registered" in result.errors


def test_atomic_rollback_behavior(monkeypatch):
    registry = ConfigRegistry()
    registry.register("first", 1, expected_type=int)
    registry.register("second", 2, expected_type=int)
    manager = ConfigReloadManager(registry)
    original_update = registry.update
    calls = []

    def failing_update(name, value):
        calls.append(name)
        if name == "second":
            raise RuntimeError("write failed")
        return original_update(name, value)

    monkeypatch.setattr(registry, "update", failing_update)

    result = manager.reload({"first": 10, "second": 20})

    assert result.valid is False
    assert "reload failed: write failed" in result.errors
    assert registry.get("first") == 1
    assert registry.get("second") == 2
    assert calls == ["first", "second"]


def test_runtime_state_exposes_configuration_registry_and_metrics():
    state = RuntimeState()

    state.config_registry.register("feature_enabled", True, expected_type=bool)
    metrics = state.get_metrics()

    assert state.get_service("config_registry") is state.config_registry
    assert state.get_service("config_reload_manager") is state.config_reload_manager
    assert metrics["configuration"]["count"] == 1
    assert metrics["configuration"]["names"] == ["feature_enabled"]
    assert metrics["resources"]["configuration_count"] == 1
    assert state.health_monitor.get_configuration_status()["configuration_count"] == 1


def test_runtime_managers_can_expose_configuration_status():
    registry = ConfigRegistry()
    registry.register("enabled", True, expected_type=bool)
    resource_manager = RuntimeResourceManager()
    health_monitor = RuntimeHealthMonitor()
    recovery_manager = RecoveryManager(health_monitor, resource_manager=resource_manager)

    resource_manager.set_config_registry(registry)
    health_monitor.set_config_registry(registry)
    recovery_manager.set_config_registry(registry)

    assert resource_manager.get_resource_metrics()["configuration_count"] == 1
    assert health_monitor.get_configuration_status()["configuration_count"] == 1
    assert recovery_manager.get_configuration_status()["configuration_count"] == 1
