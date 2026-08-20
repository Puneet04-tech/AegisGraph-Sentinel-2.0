"""
Tests for src.biometrics.analyzer.BiometricsAnalyzer
"""

import pytest

from src.biometrics.analyzer import BiometricsAnalyzer, get_biometrics_analyzer
from src.biometrics.models import (
    BiometricType,
    KeystrokeSample,
    MouseDynamicsSample,
)


def make_keystroke(**overrides) -> KeystrokeSample:
    values = dict(
        user_id="u1",
        key_press_duration=100.0,
        key_release_duration=50.0,
        flight_time=80.0,
        digraph_duration=150.0,
    )
    values.update(overrides)
    return KeystrokeSample(**values)


def make_mouse(**overrides) -> MouseDynamicsSample:
    values = dict(
        user_id="u1",
        velocity=300.0,
        acceleration=100.0,
        curvature=0.2,
        click_duration=200.0,
    )
    values.update(overrides)
    return MouseDynamicsSample(**values)


class TestProfileManagement:
    def test_create_profile(self):
        analyzer = BiometricsAnalyzer()
        profile = analyzer.create_profile("u1")
        assert profile.user_id == "u1"
        assert analyzer.get_profile("u1") is profile

    def test_get_profile_missing_returns_none(self):
        analyzer = BiometricsAnalyzer()
        assert analyzer.get_profile("nobody") is None


class TestRecording:
    def test_record_keystroke_builds_running_average(self):
        analyzer = BiometricsAnalyzer()
        analyzer.record_keystroke("u1", make_keystroke(key_press_duration=100.0))
        analyzer.record_keystroke("u1", make_keystroke(key_press_duration=200.0))
        baseline = analyzer.get_profile("u1").keystroke_profile
        assert baseline["avg_press_duration"] == pytest.approx(150.0)
        assert baseline["avg_flight_time"] == pytest.approx(80.0)

    def test_record_keystroke_creates_profile(self):
        analyzer = BiometricsAnalyzer()
        analyzer.record_keystroke("u1", make_keystroke())
        assert analyzer.get_profile("u1") is not None
        assert analyzer._keystroke_counts["u1"] == 1

    def test_record_mouse_builds_running_average(self):
        analyzer = BiometricsAnalyzer()
        analyzer.record_mouse("u1", make_mouse(velocity=300.0))
        analyzer.record_mouse("u1", make_mouse(velocity=500.0))
        baseline = analyzer.get_profile("u1").mouse_profile
        assert baseline["avg_velocity"] == pytest.approx(400.0)
        assert baseline["avg_curvature"] == pytest.approx(0.2)

    def test_record_mouse_creates_profile(self):
        analyzer = BiometricsAnalyzer()
        analyzer.record_mouse("u1", make_mouse())
        assert analyzer.get_profile("u1") is not None
        assert analyzer._mouse_counts["u1"] == 1


class TestVerifyIdentity:
    def test_unknown_user_not_verified(self):
        analyzer = BiometricsAnalyzer()
        result = analyzer.verify_identity("ghost", BiometricType.KEYSTROKE)
        assert result.verified is False
        assert result.match_score == 0.0

    def test_no_recorded_data_not_verified(self):
        analyzer = BiometricsAnalyzer()
        analyzer.create_profile("u1")
        result = analyzer.verify_identity("u1", BiometricType.KEYSTROKE)
        assert result.verified is False
        assert result.match_score == 0.0

    def test_matching_sample_verifies(self):
        analyzer = BiometricsAnalyzer()
        analyzer.record_keystroke("u1", make_keystroke())
        result = analyzer.verify_identity(
            "u1", BiometricType.KEYSTROKE, sample=make_keystroke()
        )
        assert result.match_score == pytest.approx(1.0)
        assert result.verified is True

    def test_highly_divergent_sample_fails(self):
        analyzer = BiometricsAnalyzer()
        analyzer.record_keystroke("u1", make_keystroke())
        result = analyzer.verify_identity(
            "u1",
            BiometricType.KEYSTROKE,
            sample=make_keystroke(
                key_press_duration=400.0,
                key_release_duration=200.0,
                flight_time=320.0,
                digraph_duration=600.0,
            ),
        )
        assert result.verified is False
        assert 0.0 <= result.match_score < 0.5

    def test_mouse_verification(self):
        analyzer = BiometricsAnalyzer()
        analyzer.record_mouse("u1", make_mouse())
        result = analyzer.verify_identity(
            "u1", BiometricType.MOUSE_DYNAMICS, sample=make_mouse()
        )
        assert result.match_score == pytest.approx(1.0)
        assert result.verified is True

    def test_wrong_biometric_type_not_verified(self):
        analyzer = BiometricsAnalyzer()
        analyzer.record_keystroke("u1", make_keystroke())
        result = analyzer.verify_identity("u1", BiometricType.MOUSE_DYNAMICS)
        assert result.verified is False
        assert result.match_score == 0.0

    def test_result_is_deterministic(self):
        analyzer = BiometricsAnalyzer()
        analyzer.record_keystroke("u1", make_keystroke())
        first = analyzer.verify_identity("u1", BiometricType.KEYSTROKE, sample=make_keystroke())
        second = analyzer.verify_identity("u1", BiometricType.KEYSTROKE, sample=make_keystroke())
        assert first.match_score == second.match_score
        assert first.verified == second.verified

    def test_match_score_bounds(self):
        analyzer = BiometricsAnalyzer()
        analyzer.record_keystroke("u1", make_keystroke())
        result = analyzer.verify_identity(
            "u1", BiometricType.KEYSTROKE, sample=make_keystroke(key_press_duration=99999.0)
        )
        assert 0.0 <= result.match_score <= 1.0


class TestMatchScore:
    def test_identical_values(self):
        assert BiometricsAnalyzer._match_score(
            {"a": 10.0, "b": 20.0}, {"a": 10.0, "b": 20.0}
        ) == pytest.approx(1.0)

    def test_zero_baseline_with_zero_presented(self):
        assert BiometricsAnalyzer._match_score({"a": 0.0}, {"a": 0.0}) == pytest.approx(1.0)

    def test_zero_baseline_with_positive_presented(self):
        assert BiometricsAnalyzer._match_score({"a": 0.0}, {"a": 5.0}) == pytest.approx(0.0)

    def test_empty_inputs_return_zero(self):
        assert BiometricsAnalyzer._match_score({}, {}) == 0.0


class TestSingleton:
    def test_get_biometrics_analyzer_returns_instance(self):
        analyzer = get_biometrics_analyzer()
        assert isinstance(analyzer, BiometricsAnalyzer)
        assert get_biometrics_analyzer() is analyzer
