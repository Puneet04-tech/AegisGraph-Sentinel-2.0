"""Insider threat detection must compare against a real baseline.

`_detect_anomalies` raised each anomaly on a `random.random()` comparison, and
`establish_baseline` built the baseline it compared against from
`random.uniform()` calls — so both the yardstick and the deviation from it were
invented, and the yardstick was regenerated on every call.

An accusation about a named employee is not a place for a 10% per-call chance
of firing.
"""

from __future__ import annotations

import pytest

from src.insider_threat.detector import InsiderThreatDetector
from src.insider_threat.models import ActivityType
from src.insider_threat.store import InsiderThreatStore


@pytest.fixture
def detector() -> InsiderThreatDetector:
    instance = InsiderThreatDetector(store=InsiderThreatStore())
    instance.create_profile("emp-1", "finance", "analyst")
    return instance


def history(hours=(9, 10, 11), locations=("HQ",), devices=("LAPTOP-1",), duration=100.0):
    return [
        {"hour": hour, "location": loc, "device_id": dev, "duration": duration}
        for hour in hours
        for loc in locations
        for dev in devices
    ]


def baseline_for(detector, records):
    return detector.establish_baseline("emp-1", ActivityType.LOGIN, records)


class TestBaselineIsComputed:
    """The baseline was random.uniform(1, 10) / random.uniform(30, 300)."""

    def test_frequency_counts_the_supplied_history(self, detector):
        assert baseline_for(detector, history()).avg_frequency == 3.0

    def test_duration_is_the_mean_of_the_history(self, detector):
        records = [{"duration": 100.0}, {"duration": 200.0}, {"duration": 300.0}]
        assert baseline_for(detector, records).avg_duration == pytest.approx(200.0)

    def test_the_baseline_is_stable_across_calls(self, detector):
        records = history()
        first = baseline_for(detector, records)
        second = baseline_for(detector, records)

        assert first.avg_frequency == second.avg_frequency
        assert first.avg_duration == second.avg_duration

    def test_observed_hours_locations_and_devices_are_recorded(self, detector):
        result = baseline_for(
            detector, history(hours=(7, 22), locations=("BRANCH",), devices=("PHONE-9",))
        )

        assert result.typical_hours == [7, 22]
        assert result.typical_locations == ["BRANCH"]
        assert result.typical_devices == ["PHONE-9"]

    def test_an_empty_history_yields_a_zero_baseline(self, detector):
        result = baseline_for(detector, [])
        assert result.avg_frequency == 0.0
        assert result.avg_duration == 0.0

    def test_the_module_no_longer_imports_random(self):
        import src.insider_threat.detector as module

        assert not hasattr(module, "random")


class TestAnomalyDetection:
    def _with_baseline(self, detector, **kwargs):
        baseline_for(detector, history(**kwargs))
        return detector

    def test_activity_within_the_baseline_raises_nothing(self, detector):
        self._with_baseline(detector)
        anomalies, risk = detector._detect_anomalies(
            "emp-1", ActivityType.LOGIN,
            hour=10, location="HQ", device_id="LAPTOP-1", duration=100.0,
        )
        assert anomalies == []
        assert risk == 0.0

    def test_it_is_deterministic(self, detector):
        """Previously a 10% per-call chance of UNUSUAL_TIME on clean activity."""
        self._with_baseline(detector)
        results = {
            tuple(
                detector._detect_anomalies(
                    "emp-1", ActivityType.LOGIN,
                    hour=10, location="HQ", device_id="LAPTOP-1", duration=100.0,
                )[0]
            )
            for _ in range(100)
        }
        assert results == {()}

    def test_an_unusual_hour_is_detected(self, detector):
        self._with_baseline(detector)
        anomalies, risk = detector._detect_anomalies(
            "emp-1", ActivityType.LOGIN,
            hour=3, location="HQ", device_id="LAPTOP-1", duration=100.0,
        )
        assert "UNUSUAL_TIME" in anomalies
        assert risk > 0

    def test_an_unusual_location_is_detected(self, detector):
        self._with_baseline(detector)
        anomalies, _ = detector._detect_anomalies(
            "emp-1", ActivityType.LOGIN,
            hour=10, location="OFFSHORE", device_id="LAPTOP-1", duration=100.0,
        )
        assert "UNUSUAL_LOCATION" in anomalies

    def test_an_unrecognised_device_is_detected(self, detector):
        self._with_baseline(detector)
        anomalies, _ = detector._detect_anomalies(
            "emp-1", ActivityType.LOGIN,
            hour=10, location="HQ", device_id="UNKNOWN-DEV", duration=100.0,
        )
        assert "UNRECOGNISED_DEVICE" in anomalies

    def test_an_extreme_duration_is_detected(self, detector):
        self._with_baseline(detector)
        anomalies, _ = detector._detect_anomalies(
            "emp-1", ActivityType.LOGIN,
            hour=10, location="HQ", device_id="LAPTOP-1", duration=100_000.0,
        )
        assert "UNUSUAL_DURATION" in anomalies

    def test_a_duration_just_inside_the_factor_is_not_flagged(self, detector):
        self._with_baseline(detector)
        anomalies, _ = detector._detect_anomalies(
            "emp-1", ActivityType.LOGIN,
            hour=10, location="HQ", device_id="LAPTOP-1", duration=299.0,
        )
        assert "UNUSUAL_DURATION" not in anomalies
        assert "HIGH_VOLUME_DATA_ACCESS" not in anomalies

    def test_an_extreme_data_volume_is_detected(self, detector):
        detector.establish_baseline(
            "emp-1", ActivityType.LOGIN,
            [{"hour": 10, "location": "HQ", "device_id": "LAPTOP-1",
              "duration": 100.0, "data_volume": 200.0}],
        )
        anomalies, _ = detector._detect_anomalies(
            "emp-1", ActivityType.LOGIN,
            hour=10, location="HQ", device_id="LAPTOP-1",
            duration=100.0, data_volume=5000,
        )
        assert "HIGH_VOLUME_DATA_ACCESS" in anomalies
        assert "UNUSUAL_DURATION" not in anomalies

    def test_volume_just_inside_the_factor_is_not_flagged(self, detector):
        detector.establish_baseline(
            "emp-1", ActivityType.LOGIN,
            [{"hour": 10, "location": "HQ", "device_id": "LAPTOP-1",
              "duration": 100.0, "data_volume": 200.0}],
        )
        anomalies, _ = detector._detect_anomalies(
            "emp-1", ActivityType.LOGIN,
            hour=10, location="HQ", device_id="LAPTOP-1",
            duration=100.0, data_volume=900,
        )
        assert "HIGH_VOLUME_DATA_ACCESS" not in anomalies

    def test_multiple_deviations_accumulate_risk(self, detector):
        self._with_baseline(detector)
        _, single = detector._detect_anomalies(
            "emp-1", ActivityType.LOGIN,
            hour=3, location="HQ", device_id="LAPTOP-1", duration=100.0,
        )
        _, several = detector._detect_anomalies(
            "emp-1", ActivityType.LOGIN,
            hour=3, location="OFFSHORE", device_id="UNKNOWN", duration=100.0,
        )
        assert several > single

    def test_risk_stays_within_range(self, detector):
        self._with_baseline(detector)
        _, risk = detector._detect_anomalies(
            "emp-1", ActivityType.LOGIN,
            hour=3, location="X", device_id="Y", duration=1e9,
        )
        assert 0.0 <= risk <= 1.0


class TestNoBaseline:
    def test_without_a_baseline_it_reports_insufficient_data(self, detector):
        """Neither an anomaly nor a false all-clear."""
        anomalies, risk = detector._detect_anomalies(
            "emp-1", ActivityType.LOGIN,
            hour=3, location="OFFSHORE", device_id="UNKNOWN", duration=1e6,
        )
        assert anomalies == ["INSUFFICIENT_BASELINE"]
        assert risk == 0.0

    def test_a_baseline_for_another_activity_type_does_not_apply(self, detector):
        baseline_for(detector, history())
        anomalies, _ = detector._detect_anomalies(
            "emp-2", ActivityType.FILE_DOWNLOAD, hour=3, location="X",
        )
        assert anomalies == ["INSUFFICIENT_BASELINE"]
