"""Dedicated unit tests for src/threat_hunting/behavior_analytics.py.

``BehaviorAnalyticsEngine`` builds per-entity baseline profiles and scores
behavioral deviations (off-hours, amount Z-score, unknown network, velocity)
but had no direct unit coverage.  These tests pin profile defaults/statistics
updates and every deviation dimension with deterministic fixtures.
"""

import pytest

from src.threat_hunting.behavior_analytics import BehaviorAnalyticsEngine
from src.threat_hunting.store import ThreatHuntingStore


@pytest.fixture
def engine() -> BehaviorAnalyticsEngine:
    return BehaviorAnalyticsEngine(store=ThreatHuntingStore())


def test_get_or_create_profile_seeds_defaults(engine):
    profile = engine.get_or_create_profile("user-1")
    assert profile.entity_id == "user-1"
    assert profile.typical_amount_mean == 100.0
    assert profile.typical_amount_std == 50.0
    assert profile.velocity_limit_per_min == 5
    assert engine.get_or_create_profile("user-1") is profile


def test_update_profile_statistics_computes_mean_and_std(engine):
    profile = engine.update_profile_statistics(
        "user-1", amounts=[100, 110, 90], hours=[9, 10], ips=["10.0.0.1"], devices=["d1"]
    )
    assert profile.typical_amount_mean == 100.0
    assert profile.typical_amount_std >= 1.0
    assert sorted(profile.typical_hours) == [9, 10]
    assert profile.known_ips == ["10.0.0.1"]
    assert profile.known_devices == ["d1"]


def test_update_profile_statistics_dedupes_known_devices(engine):
    profile = engine.update_profile_statistics("user-1", [], [], ["10.0.0.1", "10.0.0.1"], ["d1", "d1"])
    assert profile.known_ips == ["10.0.0.1"]
    assert profile.known_devices == ["d1"]


def test_evaluate_behavior_baseline_is_zero(engine):
    result = engine.evaluate_behavior("user-1", amount=100, hour=12, ip="1.1.1.1", device_id="d1", recent_txn_count_1m=1)
    assert result["overall_deviation"] == 0.0


def test_evaluate_behavior_flags_off_hours(engine):
    result = engine.evaluate_behavior("user-1", amount=100, hour=3, ip="1.1.1.1", device_id="d1", recent_txn_count_1m=1)
    assert result["breakdown"]["time_deviation"] == 0.5
    assert result["overall_deviation"] == pytest.approx(0.125)


def test_evaluate_behavior_flags_unknown_ip_and_device(engine):
    engine.update_profile_statistics("user-1", [], [], ["10.0.0.1"], ["known-device"])
    result = engine.evaluate_behavior("user-1", amount=100, hour=12, ip="9.9.9.9", device_id="rogue", recent_txn_count_1m=1)
    assert result["breakdown"]["network_deviation"] == 0.7


def test_evaluate_behavior_flags_velocity_over_limit(engine):
    result = engine.evaluate_behavior("user-1", amount=100, hour=12, ip="1.1.1.1", device_id="d1", recent_txn_count_1m=10)
    assert result["breakdown"]["velocity_deviation"] == pytest.approx(1.0)


def test_evaluate_behavior_flags_amount_anomaly(engine):
    result = engine.evaluate_behavior("user-1", amount=600, hour=12, ip="1.1.1.1", device_id="d1", recent_txn_count_1m=1)
    assert result["breakdown"]["amount_deviation"] == 1.0
