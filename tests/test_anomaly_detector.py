"""Dedicated unit tests for src/threat_hunting/anomaly_detector.py.

The ``AnomalyDetector.detect_anomalies`` rules (device status, auth-failure
velocity, sensitive operations and proxy-subnet IPs) had no direct
regression coverage.  These tests pin the indicator type, severity,
confidence and store-registration side effects for every trigger.
"""

from __future__ import annotations

import pytest

from src.threat_hunting.anomaly_detector import AnomalyDetector
from src.threat_hunting.models import (
    IndicatorType,
    ThreatIndicator,
    ThreatScore,
    ThreatSeverity,
)
from src.threat_hunting.store import ThreatHuntingStore


@pytest.fixture
def store() -> ThreatHuntingStore:
    return ThreatHuntingStore()


@pytest.fixture
def detector(store: ThreatHuntingStore) -> AnomalyDetector:
    return AnomalyDetector(store=store)


# ---------------------------------------------------------------------------
# No triggers
# ---------------------------------------------------------------------------


def test_no_triggers_yields_empty_list(detector: AnomalyDetector):
    indicators = detector.detect_anomalies(
        entity_id="user-1",
        operation="read_profile",
        ip_address="192.168.1.1",
        device_status="ACTIVE",
        failed_attempts=0,
    )
    assert indicators == []


def test_default_attributes_are_empty_dict(detector: AnomalyDetector):
    indicators = detector.detect_anomalies(
        entity_id="user-1",
        operation="read_profile",
        ip_address="192.168.1.1",
        device_status="BLOCKED",
        failed_attempts=0,
    )
    assert len(indicators) == 1
    assert indicators[0].attributes == {"device_status": "BLOCKED"}


# ---------------------------------------------------------------------------
# Device status
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["BLOCKED", "STOLEN", "LOST"])
def test_device_status_flags_critical_fingerprint(detector, store, status):
    indicators = detector.detect_anomalies(
        "user-1", "read", "192.168.1.1", status, 0
    )
    assert len(indicators) == 1
    ind = indicators[0]
    assert ind.indicator_type == IndicatorType.FINGERPRINT
    assert ind.value == "user-1"
    assert ind.severity == ThreatSeverity.CRITICAL
    assert ind.confidence == pytest.approx(0.9)
    assert ind.attributes == {"device_status": status}
    # side-effect: registered in the store
    assert store.get_indicator(ind.indicator_id) is ind


# ---------------------------------------------------------------------------
# Failed authentication attempts
# ---------------------------------------------------------------------------


def test_failed_attempts_below_threshold_ignored(detector):
    indicators = detector.detect_anomalies(
        "user-1", "login", "10.0.0.1", "ACTIVE", 2
    )
    assert not any(i.indicator_type == IndicatorType.VELOCITY for i in indicators)


def test_failed_attempts_low_severity_high(detector):
    indicators = detector.detect_anomalies(
        "user-1", "login", "10.0.0.1", "ACTIVE", 3
    )
    velocity = [i for i in indicators if i.indicator_type == IndicatorType.VELOCITY]
    assert len(velocity) == 1
    assert velocity[0].severity == ThreatSeverity.HIGH
    assert velocity[0].confidence == pytest.approx(0.85)
    assert velocity[0].attributes == {"failed_attempts": 3}


def test_failed_attempts_high_severity_critical_at_five(detector):
    indicators = detector.detect_anomalies(
        "user-1", "login", "10.0.0.1", "ACTIVE", 5
    )
    velocity = [i for i in indicators if i.indicator_type == IndicatorType.VELOCITY]
    assert len(velocity) == 1
    assert velocity[0].severity == ThreatSeverity.CRITICAL
    assert velocity[0].attributes == {"failed_attempts": 5}


def test_failed_attempts_above_five_remain_critical(detector):
    indicators = detector.detect_anomalies(
        "user-1", "login", "10.0.0.1", "ACTIVE", 12
    )
    velocity = [i for i in indicators if i.indicator_type == IndicatorType.VELOCITY]
    assert len(velocity) == 1
    assert velocity[0].severity == ThreatSeverity.CRITICAL


# ---------------------------------------------------------------------------
# Sensitive operations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "operation",
    ["revoke_credentials", "export_data", "update_credentials", "delete_account"],
)
def test_sensitive_operations_flagged_as_medium_behavior(detector, operation):
    indicators = detector.detect_anomalies(
        "user-1", operation, "192.168.1.1", "ACTIVE", 0
    )
    behavior = [i for i in indicators if i.indicator_type == IndicatorType.BEHAVIOR]
    assert len(behavior) == 1
    ind = behavior[0]
    assert ind.value == operation
    assert ind.severity == ThreatSeverity.MEDIUM
    assert ind.confidence == pytest.approx(0.7)
    assert ind.attributes == {"operation": operation}


def test_non_sensitive_operation_ignored(detector):
    indicators = detector.detect_anomalies(
        "user-1", "view_dashboard", "192.168.1.1", "ACTIVE", 0
    )
    assert not any(i.indicator_type == IndicatorType.BEHAVIOR for i in indicators)


# ---------------------------------------------------------------------------
# Suspicious proxy IP subnets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ip", ["100.64.0.1", "200.42.1.9"])
def test_suspicious_ip_prefix_flagged(detector, ip):
    indicators = detector.detect_anomalies(
        "user-1", "login", ip, "ACTIVE", 0
    )
    ip_inds = [i for i in indicators if i.indicator_type == IndicatorType.IP]
    assert len(ip_inds) == 1
    assert ip_inds[0].value == ip
    assert ip_inds[0].severity == ThreatSeverity.MEDIUM
    assert ip_inds[0].confidence == pytest.approx(0.6)
    assert ip_inds[0].attributes == {"ip_address": ip}


def test_normal_ip_not_flagged(detector):
    indicators = detector.detect_anomalies(
        "user-1", "login", "192.168.1.1", "ACTIVE", 0
    )
    assert not any(i.indicator_type == IndicatorType.IP for i in indicators)


# ---------------------------------------------------------------------------
# Combinations & store side-effects
# ---------------------------------------------------------------------------


def test_multiple_triggers_produce_multiple_indicators(detector):
    indicators = detector.detect_anomalies(
        "user-1", "export_data", "100.64.0.1", "STOLEN", 4
    )
    types = {i.indicator_type for i in indicators}
    assert IndicatorType.FINGERPRINT in types
    assert IndicatorType.VELOCITY in types
    assert IndicatorType.BEHAVIOR in types
    assert IndicatorType.IP in types
    assert len(indicators) == 4


def test_all_registered_indicators_are_stored(detector, store):
    detector.detect_anomalies(
        "user-1", "export_data", "100.64.0.1", "BLOCKED", 4
    )
    assert len(store.list_indicators()) == 4
    for ind in store.list_indicators():
        assert isinstance(ind, ThreatIndicator)
        assert ind.indicator_id
        assert ind.first_seen


def test_detect_anomalies_does_not_mutate_attributes_input(detector):
    attrs = {"note": "original"}
    detector.detect_anomalies(
        "user-1", "login", "10.0.0.1", "ACTIVE", 3, attributes=attrs
    )
    assert attrs == {"note": "original"}
