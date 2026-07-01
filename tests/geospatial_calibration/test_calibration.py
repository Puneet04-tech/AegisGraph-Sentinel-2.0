"""Tests for geospatial calibration engine."""

import math
import pytest

from src.geospatial_calibration import (
    AccuracyReport,
    CalibrationResult,
    GeospatialCalibrationEngine,
    LocationSample,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sample(slat: float, slon: float, gtlat: float = None, gtlon: float = None) -> LocationSample:
    return LocationSample(
        sensor_lat=slat,
        sensor_lon=slon,
        ground_truth_lat=gtlat,
        ground_truth_lon=gtlon,
    )


def _haversine_m(lat1, lon1, lat2, lon2):
    R = 6_371_000.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class TestLocationSample:
    def test_has_ground_truth_true(self):
        s = _sample(0.0, 0.0, 0.001, 0.001)
        assert s.has_ground_truth is True

    def test_has_ground_truth_false_when_missing(self):
        s = _sample(0.0, 0.0)
        assert s.has_ground_truth is False

    def test_calibration_result_to_dict(self):
        from src.geospatial_calibration.models import CalibrationResult
        cr = CalibrationResult(lat_bias=0.001, lon_bias=-0.002, sample_count=5, mean_error_m=120.0)
        d = cr.to_dict()
        assert d["lat_bias"] == 0.001
        assert "calibrated_at" in d


# ---------------------------------------------------------------------------
# Engine init
# ---------------------------------------------------------------------------

class TestEngineInit:
    def test_default_state(self):
        eng = GeospatialCalibrationEngine()
        assert eng.lat_bias == 0.0
        assert eng.lon_bias == 0.0
        assert eng.last_calibration is None

    def test_invalid_window_size(self):
        with pytest.raises(ValueError):
            GeospatialCalibrationEngine(window_size=0)


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------

class TestCalibration:
    def test_calibrate_no_ground_truth_returns_none(self):
        eng = GeospatialCalibrationEngine()
        eng.add_sample(_sample(10.0, 20.0))
        assert eng.calibrate() is None

    def test_calibrate_computes_bias(self):
        eng = GeospatialCalibrationEngine()
        # Sensor consistently reads 0.01 deg too low in lat
        for _ in range(5):
            eng.add_sample(_sample(10.00, 20.00, gtlat=10.01, gtlon=20.00))
        result = eng.calibrate()
        assert result is not None
        assert abs(result.lat_bias - 0.01) < 1e-9
        assert abs(result.lon_bias) < 1e-9

    def test_calibrate_updates_engine_bias(self):
        eng = GeospatialCalibrationEngine()
        eng.add_sample(_sample(10.00, 20.00, gtlat=10.02, gtlon=20.01))
        eng.calibrate()
        assert abs(eng.lat_bias - 0.02) < 1e-9
        assert abs(eng.lon_bias - 0.01) < 1e-9

    def test_last_calibration_stored(self):
        eng = GeospatialCalibrationEngine()
        eng.add_sample(_sample(0.0, 0.0, gtlat=0.001, gtlon=0.0))
        eng.calibrate()
        assert eng.last_calibration is not None
        assert eng.last_calibration.sample_count == 1


# ---------------------------------------------------------------------------
# Correction
# ---------------------------------------------------------------------------

class TestCorrection:
    def test_correction_applies_bias(self):
        eng = GeospatialCalibrationEngine()
        eng.add_sample(_sample(10.00, 20.00, gtlat=10.01, gtlon=20.005))
        eng.calibrate()
        clat, clon = eng.correct(10.00, 20.00)
        assert abs(clat - 10.01) < 1e-9
        assert abs(clon - 20.005) < 1e-9

    def test_correction_without_calibration_is_passthrough(self):
        eng = GeospatialCalibrationEngine()
        clat, clon = eng.correct(37.5, -122.0)
        assert clat == 37.5
        assert clon == -122.0


# ---------------------------------------------------------------------------
# Accuracy report
# ---------------------------------------------------------------------------

class TestAccuracyReport:
    def test_no_ground_truth_returns_zero_errors(self):
        eng = GeospatialCalibrationEngine()
        eng.add_sample(_sample(0.0, 0.0))
        report = eng.accuracy_report()
        assert report.mean_error_m == 0.0
        assert report.drift_detected is False

    def test_report_reflects_calibrated_bias(self):
        eng = GeospatialCalibrationEngine(drift_threshold_m=5.0)
        # Add a systematic 0.01-degree lat error (~1110 m) — well above threshold
        for _ in range(3):
            eng.add_sample(_sample(10.00, 20.00, gtlat=10.01, gtlon=20.00))
        eng.calibrate()
        report = eng.accuracy_report()
        assert report.drift_detected is True
        assert report.mean_error_m > 0

    def test_report_window_size(self):
        eng = GeospatialCalibrationEngine(window_size=10)
        for i in range(5):
            eng.add_sample(_sample(float(i), float(i)))
        report = eng.accuracy_report()
        assert report.window_size == 5

    def test_rolling_window_evicts_old_samples(self):
        eng = GeospatialCalibrationEngine(window_size=3)
        for i in range(5):
            eng.add_sample(_sample(float(i), float(i)))
        stats = eng.get_stats()
        assert stats["samples_collected"] == 3


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestGetStats:
    def test_stats_keys_present(self):
        eng = GeospatialCalibrationEngine()
        stats = eng.get_stats()
        assert "window_size" in stats
        assert "samples_collected" in stats
        assert "lat_bias" in stats
        assert "lon_bias" in stats
        assert "drift_detected" in stats
