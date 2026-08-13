"""
Unit tests for UTC timestamp normalization and PSI feature drift monitoring (Issue #3458).
"""

import pytest
from datetime import datetime, timezone, timedelta
from src.features.velocity_calculator import normalize_utc_timestamp
from src.inference.production_scorer import validate_and_normalize_timestamp, VelocityPSIDriftMonitor


def test_normalize_utc_timestamp_variations():
    # ISO string with UTC Z
    ts_z = "2026-08-09T12:00:00Z"
    epoch_z = normalize_utc_timestamp(ts_z)
    assert isinstance(epoch_z, float)

    # ISO string with offset (+05:30)
    ts_ist = "2026-08-09T17:30:00+05:30"
    epoch_ist = normalize_utc_timestamp(ts_ist)

    # Both timestamps represent the exact same UTC moment
    assert abs(epoch_z - epoch_ist) < 1.0


def test_normalize_utc_timestamp_rejection():
    with pytest.raises(ValueError):
        normalize_utc_timestamp("invalid-date-string")

    with pytest.raises(ValueError):
        normalize_utc_timestamp("")


def test_velocity_psi_drift_monitor():
    monitor = VelocityPSIDriftMonitor(num_bins=5)

    # Calibrated normal distribution scores
    scores_normal = [0.1, 0.3, 0.5, 0.7, 0.9, 0.2, 0.4, 0.6, 0.8]
    psi_normal = monitor.calculate_psi(scores_normal)

    assert psi_normal < 0.10  # Low drift

    # Heavily skewed scores (drift alert)
    scores_skewed = [0.99, 0.98, 0.97, 0.99, 0.96, 0.95, 0.98]
    psi_skewed = monitor.calculate_psi(scores_skewed)

    assert psi_skewed > 0.10  # Drift detected
