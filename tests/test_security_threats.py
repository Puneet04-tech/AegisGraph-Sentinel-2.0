"""Focused tests for in-memory runtime threat detection."""

from __future__ import annotations

from datetime import datetime, timezone

from src.runtime import RuntimeState
from src.security.threats import AbuseTracker, Threat, ThreatDetector, ThreatMetrics, ThreatRegistry


def test_threat_creation():
    threat = Threat(
        threat_id="threat-1",
        threat_type="authorization_denied",
        severity="HIGH",
        created_at=datetime.now(timezone.utc),
        metadata={"count": 10},
    )

    assert threat.severity == "high"
    assert threat.metadata["count"] == 10


def test_registry_retention():
    registry = ThreatRegistry(max_threats=2)
    first = Threat("one", "authorization_denied", "low", datetime.now(timezone.utc))
    second = Threat("two", "policy_violation", "medium", datetime.now(timezone.utc))
    third = Threat("three", "recovery_abuse", "high", datetime.now(timezone.utc))

    registry.add_threat(first)
    registry.add_threat(second)
    registry.add_threat(third)

    assert registry.list_threats() == [second, third]
    assert registry.get_threat(first.threat_id) is None


def test_severity_counting():
    registry = ThreatRegistry()
    registry.add_threat(Threat("one", "a", "low", datetime.now(timezone.utc)))
    registry.add_threat(Threat("two", "b", "HIGH", datetime.now(timezone.utc)))
    registry.add_threat(Threat("three", "c", "high", datetime.now(timezone.utc)))

    assert registry.count_by_severity() == {"low": 1, "high": 2}


def test_abuse_tracking():
    tracker = AbuseTracker()

    assert tracker.record_event("authorization_denied") == 1
    assert tracker.record_event("authorization_denied") == 2
    assert tracker.get_count("authorization_denied") == 2

    tracker.reset("authorization_denied")

    assert tracker.get_count("authorization_denied") == 0


def test_threat_detection_threshold():
    registry = ThreatRegistry()
    detector = ThreatDetector(registry, AbuseTracker(), audit_logger=None)

    threats = [detector.detect("authorization_denied") for _ in range(5)]

    assert threats[:-1] == [None, None, None, None]
    assert threats[-1] is not None
    assert threats[-1].severity == "medium"
    assert registry.count_by_severity() == {"medium": 1}


def test_threat_escalation_creates_incident():
    state = RuntimeState()

    threats = [state.threat_detector.detect("authorization_denied") for _ in range(10)]

    assert threats[4].severity == "medium"
    assert threats[9].severity == "high"
    assert state.threat_registry.count_by_severity() == {"medium": 1, "high": 1}
    assert state.incident_manager.get_metrics()["total"] == 1
    assert state.incident_registry.list_incidents()[0].metadata["threat_id"] == threats[9].threat_id


def test_metrics_generation():
    tracker = AbuseTracker()
    registry = ThreatRegistry()
    metrics = ThreatMetrics(registry, tracker)
    tracker.record_event("policy_violation")
    registry.add_threat(Threat("one", "policy_violation", "medium", datetime.now(timezone.utc)))

    assert metrics.as_dict() == {
        "active_threat_count": 1,
        "severity_counts": {"medium": 1},
        "tracked_event_counts": {"policy_violation": 1},
    }


def test_incident_integration_is_fail_safe():
    class BrokenIncidentManager:
        def create_incident(self, *args, **kwargs):
            raise RuntimeError("boom")

    detector = ThreatDetector(
        ThreatRegistry(),
        AbuseTracker(),
        incident_manager=BrokenIncidentManager(),
        audit_logger=None,
    )

    threat = None
    for _ in range(10):
        threat = detector.detect("recovery_abuse")

    assert threat is not None
    assert threat.severity == "high"


def test_runtime_integration_metrics():
    state = RuntimeState()

    for _ in range(5):
        state.threat_detector.detect("resource_throttling")
    metrics = state.get_metrics()

    assert state.get_service("threat_registry") is state.threat_registry
    assert state.get_service("abuse_tracker") is state.abuse_tracker
    assert state.get_service("threat_detector") is state.threat_detector
    assert metrics["threat_count"] == 1
    assert metrics["severity_counts"]["medium"] == 1
    assert metrics["tracked_events"]["resource_throttling"] == 5
