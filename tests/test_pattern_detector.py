"""Dedicated unit tests for src/threat_hunting/pattern_detector.py.

``AttackPatternDetector`` recognizes account-takeover, rapid device switching
and circular-transfer patterns from event/relationship streams but had no
direct unit coverage.  These tests pin each detection rule and its store
side-effects with deterministic fixtures.
"""

import pytest

from src.threat_hunting.pattern_detector import AttackPatternDetector
from src.threat_hunting.models import IndicatorType, ThreatSeverity
from src.threat_hunting.store import ThreatHuntingStore


@pytest.fixture
def detector() -> AttackPatternDetector:
    return AttackPatternDetector(store=ThreatHuntingStore())


def test_detect_ato_pattern(detector):
    events = [
        {"event_type": "auth_failed"},
        {"event_type": "auth_failed"},
        {"event_type": "credential_update"},
        {"event_type": "transaction", "amount": 5000},
    ]
    indicators = detector.detect_patterns("user-1", events, [])
    assert len(indicators) == 1
    assert indicators[0].indicator_type == IndicatorType.BEHAVIOR
    assert indicators[0].severity == ThreatSeverity.CRITICAL
    assert indicators[0].attributes["failed_logins"] == 2


def test_detect_ato_requires_large_transaction(detector):
    events = [
        {"event_type": "auth_failed"},
        {"event_type": "auth_failed"},
        {"event_type": "credential_update"},
        {"event_type": "transaction", "amount": 100},
    ]
    assert detector.detect_patterns("user-1", events, []) == []


def test_detect_rapid_device_switching(detector):
    events = [
        {"event_type": "login", "device_id": "dev-1"},
        {"event_type": "login", "device_id": "dev-2"},
        {"event_type": "login", "device_id": "dev-3"},
    ]
    indicators = detector.detect_patterns("user-1", events, [])
    assert len(indicators) == 1
    assert indicators[0].indicator_type == IndicatorType.FINGERPRINT
    assert indicators[0].severity == ThreatSeverity.HIGH


def test_detect_circular_transfer_loop(detector):
    relationships = [
        {"from_id": "A", "to_id": "B", "type": "transfer"},
        {"from_id": "B", "to_id": "C", "type": "transfer"},
        {"from_id": "C", "to_id": "A", "type": "transfer"},
    ]
    indicators = detector.detect_patterns("user-1", [], relationships)
    assert len(indicators) == 1
    assert indicators[0].indicator_type == IndicatorType.VELOCITY
    assert indicators[0].severity == ThreatSeverity.CRITICAL
    assert ["A", "B", "C", "A"] in indicators[0].attributes["loops"]


def test_no_patterns_returns_empty(detector):
    assert detector.detect_patterns("user-1", [], []) == []


def test_detect_transfer_loops_two_node_cycle(detector):
    loops = detector._detect_transfer_loops(
        [
            {"from_id": "A", "to_id": "B", "type": "transfer"},
            {"from_id": "B", "to_id": "A", "type": "transfer"},
        ]
    )
    assert loops == [["A", "B", "A"]]


def test_indicators_persisted_to_store(detector):
    events = [
        {"event_type": "login", "device_id": "dev-1"},
        {"event_type": "login", "device_id": "dev-2"},
        {"event_type": "login", "device_id": "dev-3"},
    ]
    detector.detect_patterns("user-1", events, [])
    assert len(detector.store.list_indicators()) == 1
