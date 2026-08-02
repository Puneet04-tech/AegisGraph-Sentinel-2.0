"""
Tests for src.features.behavioral_biometrics
"""

import math

import pytest

from src.features.behavioral_biometrics import (
    KeystrokeDynamicsAnalyzer,
    KeystrokeEvent,
    KeystrokeSequence,
    LightweightBiometricModel,
    _safe_float,
    analyze_keystroke_data,
)


class TestAnalyzeKeystrokeData:
    def test_valid_input_returns_features_and_stress(self):
        result = analyze_keystroke_data(
            press_times=[0.0, 0.1, 0.2, 0.3],
            release_times=[0.06, 0.16, 0.26, 0.36],
            key_ids=["a", "b", "c", "d"],
            is_backspace=[False, False, False, False],
        )
        assert result["total_events"] == 4
        assert 0.0 <= result["stress_score"] <= 1.0
        assert "wpm" in result
        assert "error_rate" in result
        assert "is_stressed" in result

    def test_empty_press_times_returns_empty_features(self):
        result = analyze_keystroke_data(press_times=[], release_times=[])
        assert result["total_events"] == 0
        assert result["hold_time_mean"] == 0.0
        assert result["wpm"] == 0.0
        assert result["stress_score"] < 1.0
        assert result["is_stressed"] is False

    def test_press_release_length_mismatch_returns_empty_features(self):
        result = analyze_keystroke_data(
            press_times=[0.0, 0.1, 0.2],
            release_times=[0.06, 0.16],
        )
        assert result["total_events"] == 0

    def test_key_ids_length_mismatch_raises(self):
        with pytest.raises(ValueError):
            analyze_keystroke_data(
                press_times=[0.0, 0.1, 0.2],
                release_times=[0.06, 0.16, 0.26],
                key_ids=["a", "b"],
            )

    def test_is_backspace_length_mismatch_raises(self):
        with pytest.raises(ValueError):
            analyze_keystroke_data(
                press_times=[0.0, 0.1, 0.2],
                release_times=[0.06, 0.16, 0.26],
                is_backspace=[False],
            )

    def test_optional_lists_default_to_match_press_times(self):
        result = analyze_keystroke_data(
            press_times=[0.0, 0.1, 0.2],
            release_times=[0.06, 0.16, 0.26],
        )
        assert result["total_events"] == 3
        assert result["backspace_count"] == 0

    def test_backspaces_counted_in_error_rate(self):
        result = analyze_keystroke_data(
            press_times=[0.0, 0.1, 0.2, 0.3],
            release_times=[0.06, 0.16, 0.26, 0.36],
            is_backspace=[True, False, False, False],
        )
        assert result["backspace_count"] == 1
        assert result["error_rate"] == pytest.approx(0.25)


class TestKeystrokeDynamicsAnalyzer:
    def test_extract_features_requires_two_events(self):
        analyzer = KeystrokeDynamicsAnalyzer()
        sequence = KeystrokeSequence(
            events=[KeystrokeEvent("a", 0.0, 0.05)],
            session_start=0.0,
            session_end=0.05,
        )
        features = analyzer.extract_features(sequence)
        assert features["total_events"] == 0

    def test_extract_features_full_timing_stats(self):
        analyzer = KeystrokeDynamicsAnalyzer()
        events = [
            KeystrokeEvent("a", 0.0, 0.05),
            KeystrokeEvent("b", 0.1, 0.15),
            KeystrokeEvent("c", 0.2, 0.25),
        ]
        sequence = KeystrokeSequence(events=events, session_start=0.0, session_end=0.25)
        features = analyzer.extract_features(sequence)
        assert features["total_events"] == 3
        assert features["hold_time_mean"] == pytest.approx(50.0)
        assert features["flight_time_mean"] == pytest.approx(50.0)
        assert features["session_duration"] == pytest.approx(0.25)
        assert features["backspace_ratio"] == 0.0

    def test_detect_stress_returns_bounded_scores(self):
        analyzer = KeystrokeDynamicsAnalyzer()
        features = analyzer._empty_features()
        features.update({"hold_time_cv": 0.5, "wpm": 10.0, "error_rate": 0.3})
        stress = analyzer.detect_stress(features)
        assert "stress_score" in stress
        assert 0.0 <= stress["stress_score"] <= 1.0
        assert set(stress) >= {"is_stressed", "wpm_stress", "error_stress"}

    def test_detect_stress_with_user_baseline_outlier(self):
        analyzer = KeystrokeDynamicsAnalyzer()
        features = analyzer._empty_features()
        features.update(
            {
                "hold_time_mean": 300.0,
                "flight_time_mean": 500.0,
                "hold_time_cv": 0.9,
                "wpm": 5.0,
                "error_rate": 0.6,
            }
        )
        baseline = {"hold_time_mean": 120.0, "hold_time_std": 15.0}
        stress = analyzer.detect_stress(features, user_baseline=baseline)
        assert stress["is_stressed"] is True

    def test_compute_wpm_excludes_backspaces(self):
        analyzer = KeystrokeDynamicsAnalyzer()
        sequence = KeystrokeSequence(
            events=[
                KeystrokeEvent("a", 0.0, 0.05),
                KeystrokeEvent("b", 0.1, 0.15, is_backspace=True),
                KeystrokeEvent("c", 0.2, 0.25),
            ],
            session_start=0.0,
            session_end=0.25,
        )
        assert analyzer._compute_wpm(sequence) == pytest.approx((2 / 5.0) / (0.25 / 60.0))

    def test_compute_wpm_zero_duration(self):
        analyzer = KeystrokeDynamicsAnalyzer()
        sequence = KeystrokeSequence(
            events=[KeystrokeEvent("a", 0.0, 0.05)],
            session_start=0.0,
            session_end=0.0,
        )
        assert analyzer._compute_wpm(sequence) == 0.0

    def test_compute_error_rate_empty(self):
        analyzer = KeystrokeDynamicsAnalyzer()
        assert analyzer._compute_error_rate([]) == 0.0

    def test_compute_rhythm_consistency_bounds(self):
        analyzer = KeystrokeDynamicsAnalyzer()
        assert analyzer._compute_rhythm_consistency([0.1]) == 0.5
        consistent = analyzer._compute_rhythm_consistency([0.1, 0.1, 0.1])
        assert 0.0 < consistent <= 1.0

    def test_coerce_sequence_from_dicts(self):
        analyzer = KeystrokeDynamicsAnalyzer()
        sequence = analyzer._coerce_sequence(
            [
                {"key": "a", "timestamp": 0.0, "event_type": "keydown"},
                {"key": "backspace", "timestamp": 0.1, "event_type": "keyup"},
            ]
        )
        assert len(sequence.events) == 2
        assert sequence.events[0].key_id == "a"
        assert sequence.events[1].is_backspace is True

    def test_coerce_sequence_empty(self):
        analyzer = KeystrokeDynamicsAnalyzer()
        sequence = analyzer._coerce_sequence([])
        assert sequence.events == []
        assert sequence.session_start == 0.0

    def test_analyze_wrapper_combines_features_and_stress(self):
        analyzer = KeystrokeDynamicsAnalyzer()
        result = analyzer.analyze(
            [
                {"key": "a", "timestamp": 0.0, "event_type": "keydown"},
                {"key": "b", "timestamp": 0.1, "event_type": "keydown"},
            ]
        )
        assert "total_events" in result
        assert "stress_score" in result


class TestSafeFloat:
    def test_returns_value_for_finite(self):
        assert _safe_float(3.14) == 3.14

    def test_returns_fallback_for_nan(self):
        assert _safe_float(float("nan"), fallback=1.0) == 1.0

    def test_returns_fallback_for_inf(self):
        assert _safe_float(float("inf"), fallback=-1.0) == -1.0
        assert _safe_float(float("-inf"), fallback=-1.0) == -1.0


class TestLightweightBiometricModel:
    def test_predict_proba_requires_trained_model(self):
        model = LightweightBiometricModel()
        with pytest.raises(ValueError):
            model.predict_proba(
                {
                    "hold_time_cv": 0.2,
                    "flight_time_cv": 0.2,
                    "wpm": 40.0,
                    "error_rate": 0.1,
                    "rhythm_consistency": 0.8,
                }
            )

    def test_train_and_predict_proba_with_sklearn(self):
        try:
            from sklearn.ensemble import GradientBoostingClassifier
        except ImportError:
            pytest.skip("sklearn not available")
        model = LightweightBiometricModel()
        model.model = GradientBoostingClassifier(n_estimators=10, random_state=42)
        import numpy as np

        X = np.array([[0.1, 0.1, 40, 0.05, 0.9]] * 10)
        y = np.array([0] * 5 + [1] * 5)
        model.model.fit(X, y)
        prob = model.predict_proba(
            {
                "hold_time_cv": 0.1,
                "flight_time_cv": 0.1,
                "wpm": 40.0,
                "error_rate": 0.05,
                "rhythm_consistency": 0.9,
            }
        )
        assert 0.0 <= prob <= 1.0
