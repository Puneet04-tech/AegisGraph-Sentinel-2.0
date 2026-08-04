"""Unit tests for the insider threat detector and store.

Covers ``src.insider_threat.store.InsiderThreatStore`` and
``src.insider_threat.detector.InsiderThreatDetector`` including risk
scoring, anomaly-based threat indicators, and threat-level evolution.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.insider_threat.detector import (
    InsiderThreatDetector,
    get_insider_detector,
)
from src.insider_threat.models import ActivityType, ThreatIndicator, ThreatLevel
from src.insider_threat.store import InsiderThreatStore


@pytest.fixture
def store() -> InsiderThreatStore:
    return InsiderThreatStore()


@pytest.fixture
def detector(store: InsiderThreatStore) -> InsiderThreatDetector:
    return InsiderThreatDetector(store=store)


# ---------------------------------------------------------------------------
# InsiderThreatStore
# ---------------------------------------------------------------------------


class TestStore:
    def test_store_profile_round_trip(self, store):
        profile = _make_profile(store, "emp-1")

        assert store.get_profile(profile.profile_id) is profile
        assert store.get_employee_profile("emp-1") is profile
        assert store.get_employee_profile("missing") is None

    def test_store_baseline_and_lookup(self, store):
        baseline = _make_baseline(store, "emp-1", ActivityType.LOGIN)

        stored = store.get_employee_baselines("emp-1")
        assert stored == [baseline]

    def test_activities_sorted_newest_first(self, store):
        old = _make_activity(store, "emp-1", days_ago=2)
        new = _make_activity(store, "emp-1", days_ago=0)

        activities = store.get_employee_activities("emp-1")
        assert activities == [new, old]

    def test_activities_respect_limit(self, store):
        for i in range(5):
            _make_activity(store, "emp-1", days_ago=i)

        assert len(store.get_employee_activities("emp-1", limit=3)) == 3

    def test_indicator_storage_and_active_filter(self, store):
        resolved = store.store_indicator(
            ThreatIndicator(
                employee_id="emp-1",
                indicator_type="UNUSUAL_TIME",
                severity=ThreatLevel.MEDIUM,
                description="d",
                confidence=0.8,
                resolved=True,
            )
        )
        active = store.store_indicator(
            ThreatIndicator(
                employee_id="emp-1",
                indicator_type="PRIVILEGE_ESCALATION",
                severity=ThreatLevel.CRITICAL,
                description="d",
                confidence=0.8,
            )
        )

        assert store.get_employee_indicators("emp-1") == [resolved, active]
        assert store.get_active_indicators() == [active]

    def test_stats_counts(self, store):
        _make_profile(store, "emp-1")
        _make_activity(store, "emp-1")

        stats = store.get_stats()
        assert stats["profiles"] == 1
        assert stats["activities"] == 1


# ---------------------------------------------------------------------------
# Helpers (kept after usage for clarity)
# ---------------------------------------------------------------------------


def _make_profile(store: InsiderThreatStore, employee_id: str):
    from src.insider_threat.models import InsiderProfile

    return store.store_profile(
        InsiderProfile(employee_id=employee_id, department="finance", role="analyst")
    )


def _make_baseline(store: InsiderThreatStore, employee_id: str, activity_type: ActivityType):
    from src.insider_threat.models import BehavioralBaseline

    return store.store_baseline(
        BehavioralBaseline(
            employee_id=employee_id,
            activity_type=activity_type,
            avg_frequency=5.0,
            avg_duration=120.0,
        )
    )


def _make_activity(store: InsiderThreatStore, employee_id: str, days_ago: int = 0):
    from src.insider_threat.models import ActivityRecord

    return store.store_activity(
        ActivityRecord(
            employee_id=employee_id,
            activity_type=ActivityType.FILE_ACCESS,
            resource_accessed="r",
            location="HQ",
            device_id="LAPTOP-001",
            duration_seconds=10,
            data_volume=100,
            timestamp=datetime.now(timezone.utc) - timedelta(days=days_ago),
        )
    )


# ---------------------------------------------------------------------------
# InsiderThreatDetector
# ---------------------------------------------------------------------------


class TestDetector:
    def test_create_profile_stores(self, store):
        detector = InsiderThreatDetector(store=store)
        profile = detector.create_profile("emp-1", "finance", "analyst")

        assert profile.employee_id == "emp-1"
        assert store.get_employee_profile("emp-1") is profile

    def test_establish_baseline_sets_flag(self, store):
        detector = InsiderThreatDetector(store=store)
        detector.create_profile("emp-1", "finance", "analyst")

        baseline = detector.establish_baseline("emp-1", ActivityType.LOGIN, [])

        assert baseline.employee_id == "emp-1"
        assert store.get_employee_profile("emp-1").baseline_established is True
        assert 1 <= baseline.avg_frequency <= 10

    def test_record_activity_persists_fields(self, store):
        detector = InsiderThreatDetector(store=store)
        detector.create_profile("emp-1", "finance", "analyst")

        activity = detector.record_activity(
            "emp-1", ActivityType.DATA_EXPORT, "db", "BRANCH", "LAPTOP-002",
            duration=60.0, data_volume=5000,
        )

        assert activity.resource_accessed == "db"
        assert activity.duration_seconds == 60.0
        assert activity.data_volume == 5000
        assert 0.0 <= activity.risk_score_contribution <= 1.0
        assert store.get_employee_activities("emp-1") == [activity]

    def test_record_activity_creates_indicator_when_risky(self, store, monkeypatch):
        detector = InsiderThreatDetector(store=store)
        detector.create_profile("emp-1", "finance", "analyst")
        monkeypatch.setattr(
            detector, "_detect_anomalies", lambda emp, typ: (["UNUSUAL_TIME"], 0.5)
        )

        activity = detector.record_activity("emp-1", ActivityType.LOGIN, "r", "HQ", "D")

        assert activity.anomalies == ["UNUSUAL_TIME"]
        indicators = store.get_employee_indicators("emp-1")
        assert len(indicators) == 1
        assert indicators[0].severity == ThreatLevel.MEDIUM
        assert indicators[0].employee_id == "emp-1"

    def test_privilege_escalation_indicator_is_critical(self, store, monkeypatch):
        detector = InsiderThreatDetector(store=store)
        detector.create_profile("emp-1", "finance", "analyst")
        monkeypatch.setattr(
            detector, "_detect_anomalies",
            lambda emp, typ: (["PRIVILEGE_ESCALATION"], 0.5),
        )

        detector.record_activity("emp-1", ActivityType.PRIVILEGE_ESCALATION, "r", "HQ", "D")

        indicator = store.get_employee_indicators("emp-1")[0]
        assert indicator.severity == ThreatLevel.CRITICAL

    def test_high_volume_access_indicator_is_high(self, store, monkeypatch):
        detector = InsiderThreatDetector(store=store)
        detector.create_profile("emp-1", "finance", "analyst")
        monkeypatch.setattr(
            detector, "_detect_anomalies",
            lambda emp, typ: (["HIGH_VOLUME_DATA_ACCESS"], 0.5),
        )

        detector.record_activity("emp-1", ActivityType.FILE_DOWNLOAD, "r", "HQ", "D")

        indicator = store.get_employee_indicators("emp-1")[0]
        assert indicator.severity == ThreatLevel.HIGH

    def test_low_risk_activity_creates_no_indicator(self, store, monkeypatch):
        detector = InsiderThreatDetector(store=store)
        detector.create_profile("emp-1", "finance", "analyst")
        monkeypatch.setattr(
            detector, "_detect_anomalies", lambda emp, typ: ([], 0.1)
        )

        detector.record_activity("emp-1", ActivityType.EMAIL, "r", "HQ", "D")

        assert store.get_employee_indicators("emp-1") == []

    def test_risk_score_evolves_and_reaches_critical(self, store):
        detector = InsiderThreatDetector(store=store)
        profile = detector.create_profile("emp-1", "finance", "analyst")
        profile.risk_score = 0.85
        store.store_profile(profile)
        activity = _make_activity(store, "emp-1")
        activity.risk_score_contribution = 1.0
        store.store_activity(activity)

        detector._update_risk_score("emp-1")

        updated = store.get_employee_profile("emp-1")
        assert updated.risk_score > 0.8
        assert updated.threat_level == ThreatLevel.CRITICAL

    def test_risk_score_reaches_medium(self, store):
        detector = InsiderThreatDetector(store=store)
        profile = detector.create_profile("emp-1", "finance", "analyst")
        profile.risk_score = 0.3
        store.store_profile(profile)
        activity = _make_activity(store, "emp-1")
        activity.risk_score_contribution = 1.0
        store.store_activity(activity)

        detector._update_risk_score("emp-1")

        updated = store.get_employee_profile("emp-1")
        assert 0.3 < updated.risk_score <= 0.6
        assert updated.threat_level == ThreatLevel.MEDIUM

    def test_risk_score_reaches_high(self, store):
        detector = InsiderThreatDetector(store=store)
        profile = detector.create_profile("emp-1", "finance", "analyst")
        profile.risk_score = 0.5
        store.store_profile(profile)
        activity = _make_activity(store, "emp-1")
        activity.risk_score_contribution = 1.0
        store.store_activity(activity)

        detector._update_risk_score("emp-1")

        updated = store.get_employee_profile("emp-1")
        assert 0.6 < updated.risk_score <= 0.8
        assert updated.threat_level == ThreatLevel.HIGH

    def test_low_risk_activity_keeps_low_level(self, store):
        detector = InsiderThreatDetector(store=store)
        detector.create_profile("emp-1", "finance", "analyst")
        activity = _make_activity(store, "emp-1")
        activity.risk_score_contribution = 0.2
        store.store_activity(activity)

        detector._update_risk_score("emp-1")

        assert store.get_employee_profile("emp-1").threat_level == ThreatLevel.LOW

    def test_get_high_risk_employees_threshold(self, store):
        detector = InsiderThreatDetector(store=store)
        low = detector.create_profile("emp-1", "finance", "analyst")
        high = detector.create_profile("emp-2", "it", "admin")
        low.risk_score = 0.2
        high.risk_score = 0.7
        store.store_profile(low)
        store.store_profile(high)

        high_risk = detector.get_high_risk_employees(threshold=0.5)

        assert high_risk == [high]

    def test_resolve_indicator(self, store):
        detector = InsiderThreatDetector(store=store)
        detector.create_profile("emp-1", "finance", "analyst")
        indicator = store.store_indicator(
            ThreatIndicator(
                employee_id="emp-1",
                indicator_type="UNUSUAL_TIME",
                severity=ThreatLevel.MEDIUM,
                description="d",
                confidence=0.8,
            )
        )

        resolved = detector.resolve_indicator(indicator.indicator_id)

        assert resolved.resolved is True
        assert detector.get_active_indicators() == []


class TestSingleton:
    def test_get_insider_detector_returns_same_instance(self, store):
        first = get_insider_detector(store=store)
        second = get_insider_detector(store=store)

        assert first is second
        assert isinstance(first, InsiderThreatDetector)
