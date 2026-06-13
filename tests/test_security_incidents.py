"""Focused tests for in-memory security incidents."""

from __future__ import annotations

from src.runtime import RuntimeState
from src.security.incidents import ContainmentManager, IncidentManager, IncidentRegistry


def test_incident_creation():
    registry = IncidentRegistry()

    incident = registry.create_incident("runtime_abuse", "HIGH", {"actor": "test"})

    assert incident.incident_id
    assert incident.incident_type == "runtime_abuse"
    assert incident.severity == "high"
    assert incident.metadata["actor"] == "test"
    assert incident.contained is False


def test_incident_lookup():
    registry = IncidentRegistry()
    incident = registry.create_incident("policy_bypass", "medium")

    assert registry.get_incident(incident.incident_id) is incident
    assert registry.get_incident("missing") is None


def test_retention_behavior():
    registry = IncidentRegistry(max_incidents=2)
    first = registry.create_incident("one", "low")
    second = registry.create_incident("two", "medium")
    third = registry.create_incident("three", "high")

    assert registry.list_incidents() == [second, third]
    assert registry.get_incident(first.incident_id) is None


def test_severity_counting():
    registry = IncidentRegistry()
    registry.create_incident("one", "low")
    registry.create_incident("two", "HIGH")
    registry.create_incident("three", "high")

    assert registry.count_by_severity() == {"low": 1, "high": 2}


def test_containment_activation():
    manager = ContainmentManager()

    flags = manager.activate_containment()

    assert flags == {
        "event_throttled": True,
        "recovery_suppressed": True,
        "admin_cooldown": True,
    }


def test_containment_release():
    manager = ContainmentManager()
    manager.activate_containment()

    flags = manager.deactivate_containment()

    assert flags == {
        "event_throttled": False,
        "recovery_suppressed": False,
        "admin_cooldown": False,
    }


def test_incident_metrics():
    manager = IncidentManager(audit_logger=None)
    manager.create_incident("probe", "low")
    manager.create_incident("breakout", "critical")

    metrics = manager.get_metrics()

    assert metrics["total"] == 2
    assert metrics["by_severity"] == {"low": 1, "critical": 1}
    assert metrics["contained"] == 1
    assert metrics["containment"]["event_throttled"] is True


def test_runtime_integration_metrics():
    state = RuntimeState()

    incident = state.incident_manager.create_incident("runtime_intrusion", "critical")
    metrics = state.get_metrics()

    assert state.get_service("incident_registry") is state.incident_registry
    assert state.get_service("incident_manager") is state.incident_manager
    assert state.incident_registry.get_incident(incident.incident_id) is incident
    assert metrics["incidents"]["total"] == 1
    assert metrics["incidents"]["by_severity"]["critical"] == 1
    assert metrics["incidents"]["contained"] == 1
