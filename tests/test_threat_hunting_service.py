"""Dedicated unit tests for src/threat_hunting/service.py.

``ThreatHuntingService`` is the facade coordinating behavior scoring, anomaly
detection, intel enrichment, attack-path discovery, threat scoring, hunts and
correlations.  These tests pin the end-to-end threat evaluation pipeline,
severity escalation, hunt lifecycle, correlation weighting and dashboard stats
with deterministic fixtures.
"""

import pytest

from src.threat_hunting.service import ThreatHuntingService
from src.threat_hunting.models import (
    HuntState,
    IndicatorType,
    ThreatCorrelation,
    ThreatIndicator,
    ThreatScore,
    ThreatSeverity,
)
from src.threat_hunting.store import ThreatHuntingStore


@pytest.fixture
def service() -> ThreatHuntingService:
    return ThreatHuntingService(store=ThreatHuntingStore())


def test_evaluate_baseline_is_low(service):
    score = service.evaluate_entity_threat("user-1", amount=100, hour=12)
    assert score.score == 0.0
    assert score.severity == ThreatSeverity.LOW
    assert score.entity_id == "user-1"


def test_evaluate_with_malicious_ip_raises_score(service):
    baseline = service.evaluate_entity_threat("user-1", amount=100, hour=12)
    enriched = service.evaluate_entity_threat("user-1", amount=100, hour=12, ip_address="198.51.100.42")
    assert enriched.score > baseline.score
    assert len(enriched.active_indicators) == 1


def test_evaluate_with_blocked_device_adds_indicator(service):
    score = service.evaluate_entity_threat("user-1", device_status="BLOCKED")
    assert len(score.active_indicators) == 1


def test_evaluate_anomalous_behavior_escalates_to_medium(service):
    score = service.evaluate_entity_threat(
        "user-1", amount=600, hour=3, ip_address="198.51.100.42"
    )
    assert score.severity == ThreatSeverity.MEDIUM


def test_evaluate_records_history(service):
    service.evaluate_entity_threat("user-1")
    actions = [entry["action"] for entry in service.store.history]
    assert actions == ["evaluate_entity_threat"]


def test_start_hunt_completes(service):
    hunt = service.start_hunt("weekend-baseline", "weekly hunt", {"min_threat_score": 0.0})
    assert hunt.state == HuntState.COMPLETED
    assert service.store.get_hunt(hunt.hunt_id) is hunt


def test_correlate_threats_weights_by_severity(service):
    critical = service.store.register_indicator(
        ThreatIndicator(indicator_type=IndicatorType.IP, severity=ThreatSeverity.CRITICAL)
    )
    high = service.store.register_indicator(
        ThreatIndicator(indicator_type=IndicatorType.DOMAIN, severity=ThreatSeverity.HIGH)
    )
    correlation = service.correlate_threats(
        "linked-campaign", ["user-1", "user-2"], [critical.indicator_id, high.indicator_id]
    )
    assert isinstance(correlation, ThreatCorrelation)
    assert correlation.correlation_score == pytest.approx(0.7)


def test_correlate_threats_ignores_unknown_ids(service):
    correlation = service.correlate_threats("empty", ["user-1"], ["missing-indicator"])
    assert correlation.correlation_score == 0.0


def test_discover_attack_paths(service):
    service.store.set_threat_score(
        "C",
        ThreatScore(entity_id="C", entity_type="user", score=0.8, active_indicators=[]),
    )
    relationships = [
        {"from_id": "A", "to_id": "B", "type": "transfer"},
        {"from_id": "B", "to_id": "C", "type": "transfer"},
    ]
    paths = service.discover_attack_paths("A", relationships)
    assert len(paths) == 1
    assert [node["id"] for node in paths[0].nodes] == ["A", "B", "C"]
    assert paths[0].risk_score == 0.8


def test_get_dashboard_stats_has_expected_keys(service):
    stats = service.get_dashboard_stats()
    assert "store_stats" in stats
    assert "critical_indicators_count" in stats
    assert "campaigns" in stats
    assert "recent_hunts" in stats
