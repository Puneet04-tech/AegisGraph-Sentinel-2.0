"""Tests for PSI drift detection and real baseline management.

PSI values are checked against hand-constructed distributions whose
bin masses are known exactly, so the expected index is computed from
the definition rather than from a previous run of the code.
"""

import math

import numpy as np
import pytest

from src.mlops.drift_monitor import (
    PSI_MODERATE,
    PSI_SIGNIFICANT,
    AdversarialDriftMonitor,
    DriftReport,
    population_stability_index,
)


@pytest.fixture
def baseline_samples():
    rng = np.random.default_rng(seed=7)
    return {"flight_time": rng.normal(loc=120.0, scale=15.0, size=2000)}


@pytest.fixture
def monitor(baseline_samples):
    with AdversarialDriftMonitor(baselines=baseline_samples) as m:
        yield m


class TestPopulationStabilityIndex:
    def test_identical_distributions_have_zero_psi(self):
        data = np.linspace(0.0, 100.0, 1000)

        assert population_stability_index(data, data) == pytest.approx(0.0, abs=1e-9)

    def test_matches_definition_on_known_bin_masses(self):
        # Two bins of equal baseline mass; live sample puts 75% in the
        # lower bin instead of 50%.
        baseline = np.array([0.0] * 50 + [1.0] * 50)
        live = np.array([0.0] * 75 + [1.0] * 25)

        expected = (0.75 - 0.5) * math.log(0.75 / 0.5) + (0.25 - 0.5) * math.log(
            0.25 / 0.5
        )

        assert population_stability_index(baseline, live, bins=2) == pytest.approx(
            expected, abs=1e-6
        )

    def test_psi_is_non_negative_and_grows_with_shift(self):
        rng = np.random.default_rng(seed=3)
        baseline = rng.normal(0.0, 1.0, 5000)

        small = population_stability_index(baseline, rng.normal(0.2, 1.0, 5000))
        large = population_stability_index(baseline, rng.normal(3.0, 1.0, 5000))

        assert 0.0 <= small < large

    def test_shifted_distribution_exceeds_significant_threshold(self):
        rng = np.random.default_rng(seed=11)
        baseline = rng.normal(120.0, 15.0, 5000)
        shifted = rng.normal(160.0, 3.0, 5000)

        assert population_stability_index(baseline, shifted) > PSI_SIGNIFICANT

    def test_live_values_outside_baseline_range_are_counted(self):
        baseline = np.linspace(0.0, 1.0, 1000)
        # Entirely outside the baseline's observed range
        live = np.full(1000, 500.0)

        assert population_stability_index(baseline, live) > PSI_SIGNIFICANT

    @pytest.mark.parametrize(
        ("baseline", "live"),
        [
            ([], [1.0, 2.0]),
            ([1.0, 2.0], []),
            ([5.0] * 100, [5.0] * 100),  # degenerate: constant baseline
        ],
    )
    def test_undefined_cases_return_zero(self, baseline, live):
        assert population_stability_index(baseline, live) == 0.0


class TestEvaluateBatch:
    def test_stable_traffic_reports_no_drift(self, monitor):
        rng = np.random.default_rng(seed=21)
        report = monitor.evaluate_batch("flight_time", rng.normal(120.0, 15.0, 500))

        assert isinstance(report, DriftReport)
        assert not report.drift_detected
        assert not report
        assert report.severity == "STABLE"
        assert report.psi < PSI_MODERATE

    def test_bot_traffic_reports_significant_drift(self, monitor):
        rng = np.random.default_rng(seed=22)
        report = monitor.evaluate_batch("flight_time", rng.normal(160.0, 2.0, 500))

        assert report.drift_detected
        assert bool(report) is True
        assert report.severity == "SIGNIFICANT"
        assert report.psi >= PSI_SIGNIFICANT

    def test_report_carries_sample_sizes_and_feature(self, monitor):
        rng = np.random.default_rng(seed=23)
        report = monitor.evaluate_batch("flight_time", rng.normal(120.0, 15.0, 300))

        assert report.feature == "flight_time"
        assert report.baseline_size == 2000
        assert report.live_size == 300
        assert set(report.to_dict()) == {
            "feature", "ks_statistic", "p_value", "psi", "severity",
            "drift_detected", "baseline_size", "live_size",
        }

    def test_unknown_feature_returns_none(self, monitor):
        assert monitor.evaluate_batch("not_a_feature", [1.0, 2.0]) is None

    def test_empty_live_batch_returns_none(self, monitor):
        assert monitor.evaluate_batch("flight_time", []) is None

    def test_psi_only_drift_is_detected(self, baseline_samples):
        """A large shift is caught even when the K-S p-value is disabled."""
        rng = np.random.default_rng(seed=24)
        with AdversarialDriftMonitor(
            baselines=baseline_samples, p_value_threshold=0.0
        ) as m:
            report = m.evaluate_batch("flight_time", rng.normal(200.0, 5.0, 500))

        assert report.drift_detected
        assert report.p_value >= 0.0

    def test_alert_includes_psi(self, monitor, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            monitor, "trigger_alert",
            lambda *args, **kwargs: captured.update(kwargs),
        )
        rng = np.random.default_rng(seed=25)
        monitor.evaluate_batch("flight_time", rng.normal(160.0, 2.0, 500))

        assert "psi" in captured
        assert captured["severity"] == "SIGNIFICANT"


class TestBaselineManagement:
    def test_provided_baselines_are_used_and_not_synthetic(self, baseline_samples):
        with AdversarialDriftMonitor(baselines=baseline_samples) as m:
            assert set(m.baselines) == {"flight_time"}
            assert m.baselines_are_synthetic is False

    def test_default_baselines_are_flagged_synthetic_and_deterministic(self):
        with AdversarialDriftMonitor() as first, AdversarialDriftMonitor() as second:
            assert first.baselines_are_synthetic is True
            # Previously each instance invented a different baseline
            assert np.allclose(
                first.baselines["keystroke_flight_time"],
                second.baselines["keystroke_flight_time"],
            )

    def test_save_and_load_roundtrip(self, tmp_path, baseline_samples):
        path = str(tmp_path / "baselines.npz")
        with AdversarialDriftMonitor(baselines=baseline_samples) as m:
            m.save_baselines(path)

        with AdversarialDriftMonitor(baseline_path=path) as restored:
            assert restored.baselines_are_synthetic is False
            assert np.allclose(
                restored.baselines["flight_time"], baseline_samples["flight_time"]
            )

    def test_baseline_path_from_environment(self, tmp_path, baseline_samples, monkeypatch):
        path = str(tmp_path / "env_baselines.npz")
        with AdversarialDriftMonitor(baselines=baseline_samples) as m:
            m.save_baselines(path)

        monkeypatch.setenv("AEGIS_DRIFT_BASELINE_PATH", path)
        with AdversarialDriftMonitor() as restored:
            assert restored.baselines_are_synthetic is False
            assert "flight_time" in restored.baselines

    def test_missing_baseline_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            AdversarialDriftMonitor(baseline_path=str(tmp_path / "nope.npz"))

    def test_fit_baselines_replaces_all(self, monitor):
        monitor.fit_baselines({"amount": [1.0, 2.0, 3.0, 4.0]})

        assert set(monitor.baselines) == {"amount"}
        assert monitor.baselines_are_synthetic is False

    def test_register_baseline_adds_one_feature(self, monitor):
        monitor.register_baseline("amount", [1.0, 2.0, 3.0])

        assert set(monitor.baselines) == {"flight_time", "amount"}

    def test_registering_clears_synthetic_flag(self):
        with AdversarialDriftMonitor() as m:
            assert m.baselines_are_synthetic is True
            m.register_baseline("amount", [1.0, 2.0, 3.0])
            assert m.baselines_are_synthetic is False

    @pytest.mark.parametrize(
        "bad_baselines",
        [
            {"empty": []},
            {"nan": [1.0, float("nan")]},
            {"inf": [1.0, float("inf")]},
            {},
        ],
    )
    def test_invalid_baselines_rejected(self, bad_baselines):
        with pytest.raises(ValueError):
            AdversarialDriftMonitor(baselines=bad_baselines)
