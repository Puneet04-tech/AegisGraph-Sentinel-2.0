"""Data models for geospatial accuracy tracking and sensor calibration."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class LocationSample:
    """A single observed position with an optional ground-truth reference."""

    sensor_lat: float
    sensor_lon: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ground_truth_lat: Optional[float] = None
    ground_truth_lon: Optional[float] = None

    @property
    def has_ground_truth(self) -> bool:
        return self.ground_truth_lat is not None and self.ground_truth_lon is not None


@dataclass
class CalibrationResult:
    """Outcome of a calibration cycle."""

    lat_bias: float
    lon_bias: float
    sample_count: int
    mean_error_m: float
    calibrated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "lat_bias": self.lat_bias,
            "lon_bias": self.lon_bias,
            "sample_count": self.sample_count,
            "mean_error_m": self.mean_error_m,
            "calibrated_at": self.calibrated_at.isoformat(),
        }


@dataclass
class AccuracyReport:
    """Summary of location accuracy over a window of samples."""

    window_size: int
    mean_error_m: float
    max_error_m: float
    drift_detected: bool
    lat_bias: float
    lon_bias: float
