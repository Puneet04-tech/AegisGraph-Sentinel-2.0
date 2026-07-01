"""
Geospatial calibration engine.

Detects systematic sensor drift by accumulating location samples with known
ground-truth values, computing per-axis bias, and applying a learned
correction so that reported positions remain accurate over time.
"""

import math
from collections import deque
from typing import Deque, List, Optional, Tuple

from .models import AccuracyReport, CalibrationResult, LocationSample

_EARTH_RADIUS_M = 6_371_000.0
_DRIFT_THRESHOLD_M = 10.0  # bias magnitude above which drift is flagged


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return the great-circle distance in metres between two WGS-84 points."""
    r = _EARTH_RADIUS_M
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


class GeospatialCalibrationEngine:
    """
    Maintains a rolling window of location samples and computes a bias
    correction (lat_bias, lon_bias) from samples that include ground truth.

    Usage
    -----
    1. Call ``add_sample`` for every incoming sensor reading (with or without
       ground truth).
    2. Call ``calibrate`` periodically (or when ``drift_detected`` is True) to
       update the bias estimate.
    3. Pass raw sensor coordinates through ``correct`` to obtain bias-corrected
       coordinates before persisting or displaying them.
    """

    def __init__(self, window_size: int = 100, drift_threshold_m: float = _DRIFT_THRESHOLD_M) -> None:
        if window_size < 1:
            raise ValueError("window_size must be >= 1")
        self._window: Deque[LocationSample] = deque(maxlen=window_size)
        self._window_size = window_size
        self._drift_threshold_m = drift_threshold_m
        self._lat_bias: float = 0.0
        self._lon_bias: float = 0.0
        self._last_calibration: Optional[CalibrationResult] = None

    # ------------------------------------------------------------------
    # Sample ingestion
    # ------------------------------------------------------------------

    def add_sample(self, sample: LocationSample) -> None:
        """Add a new location reading to the rolling window."""
        self._window.append(sample)

    # ------------------------------------------------------------------
    # Calibration
    # ------------------------------------------------------------------

    def calibrate(self) -> Optional[CalibrationResult]:
        """
        Recompute the bias from samples that carry ground-truth coordinates.
        Returns a CalibrationResult or None if no ground-truth samples exist.
        """
        gt_samples = [s for s in self._window if s.has_ground_truth]
        if not gt_samples:
            return None

        lat_errors = [s.ground_truth_lat - s.sensor_lat for s in gt_samples]  # type: ignore[operator]
        lon_errors = [s.ground_truth_lon - s.sensor_lon for s in gt_samples]  # type: ignore[operator]

        self._lat_bias = sum(lat_errors) / len(lat_errors)
        self._lon_bias = sum(lon_errors) / len(lon_errors)

        errors_m = [
            _haversine_m(s.sensor_lat, s.sensor_lon, s.ground_truth_lat, s.ground_truth_lon)  # type: ignore[arg-type]
            for s in gt_samples
        ]
        mean_error_m = sum(errors_m) / len(errors_m)

        result = CalibrationResult(
            lat_bias=self._lat_bias,
            lon_bias=self._lon_bias,
            sample_count=len(gt_samples),
            mean_error_m=mean_error_m,
        )
        self._last_calibration = result
        return result

    # ------------------------------------------------------------------
    # Correction
    # ------------------------------------------------------------------

    def correct(self, lat: float, lon: float) -> Tuple[float, float]:
        """Apply the current bias correction to a raw sensor reading."""
        return lat + self._lat_bias, lon + self._lon_bias

    # ------------------------------------------------------------------
    # Accuracy reporting
    # ------------------------------------------------------------------

    def accuracy_report(self) -> AccuracyReport:
        """
        Compute an accuracy report over the current window.
        drift_detected is True when the absolute bias on either axis
        exceeds *drift_threshold_m* (converted to approximate degrees).
        """
        gt_samples = [s for s in self._window if s.has_ground_truth]

        if not gt_samples:
            return AccuracyReport(
                window_size=len(self._window),
                mean_error_m=0.0,
                max_error_m=0.0,
                drift_detected=False,
                lat_bias=self._lat_bias,
                lon_bias=self._lon_bias,
            )

        errors_m = [
            _haversine_m(s.sensor_lat, s.sensor_lon, s.ground_truth_lat, s.ground_truth_lon)  # type: ignore[arg-type]
            for s in gt_samples
        ]
        mean_err = sum(errors_m) / len(errors_m)
        max_err = max(errors_m)

        # Convert threshold from metres to approximate degrees (1 deg ~ 111 km).
        deg_threshold = self._drift_threshold_m / 111_000.0
        drift = abs(self._lat_bias) > deg_threshold or abs(self._lon_bias) > deg_threshold

        return AccuracyReport(
            window_size=len(self._window),
            mean_error_m=mean_err,
            max_error_m=max_err,
            drift_detected=drift,
            lat_bias=self._lat_bias,
            lon_bias=self._lon_bias,
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def lat_bias(self) -> float:
        return self._lat_bias

    @property
    def lon_bias(self) -> float:
        return self._lon_bias

    @property
    def last_calibration(self) -> Optional[CalibrationResult]:
        return self._last_calibration

    def get_stats(self) -> dict:
        return {
            "window_size": self._window_size,
            "samples_collected": len(self._window),
            "lat_bias": self._lat_bias,
            "lon_bias": self._lon_bias,
            "drift_detected": self.accuracy_report().drift_detected,
        }
