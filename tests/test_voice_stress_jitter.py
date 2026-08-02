"""
Tests for VoiceStressAnalyzer.detect_stress jitter scaling.

Regression coverage for the jitter_stress unit bug: `_compute_jitter`
returns a dimensionless fraction (0.005 == 0.5%), but detect_stress
multiplied it by 100, treating the fraction as an already-percent value.
At the documented ">1% indicates vocal tension" threshold the component
contributed only ~1.0/100 points, making a 20%-weight stress indicator
effectively dead. The fix normalizes against the 1% reference the same
way shimmer normalizes against its 15% reference.
"""

import pytest

from src.features.voice_stress_analysis import VoiceStressAnalyzer, VoiceFeatures


@pytest.fixture
def analyzer():
    return VoiceStressAnalyzer(stress_threshold=30.0, coercion_threshold=75.0)


def make_features(jitter=0.005, **overrides):
    """Build VoiceFeatures with sensible defaults for detect_stress."""
    defaults = dict(
        f0_mean=120.0,
        f0_std=10.0,
        f0_range=50.0,
        jitter=jitter,
        shimmer=0.05,
        speech_rate=4.5,
        prosody_entropy=3.0,
        snr=20.0,
        background_voices=1,
    )
    defaults.update(overrides)
    return VoiceFeatures(**defaults)


class TestJitterStressScaling:
    """jitter_stress must normalize against the documented 1% threshold."""

    def test_one_percent_jitter_full_stress(self, analyzer):
        result = analyzer.detect_stress(make_features(jitter=0.01))
        assert result["jitter_stress"] == pytest.approx(100.0)

    def test_half_percent_jitter_half_stress(self, analyzer):
        result = analyzer.detect_stress(make_features(jitter=0.005))
        assert result["jitter_stress"] == pytest.approx(50.0)

    def test_jitter_stress_capped_at_100(self, analyzer):
        result = analyzer.detect_stress(make_features(jitter=0.05))
        assert result["jitter_stress"] == 100.0

    def test_zero_jitter_zero_stress(self, analyzer):
        result = analyzer.detect_stress(make_features(jitter=0.0))
        assert result["jitter_stress"] == 0.0

    def test_jitter_stress_monotonic(self, analyzer):
        values = [0.001, 0.003, 0.005, 0.007, 0.009]
        scores = [
            analyzer.detect_stress(make_features(jitter=j))["jitter_stress"]
            for j in values
        ]
        assert scores == sorted(scores)
        assert scores[0] < scores[-1]

    def test_jitter_stress_matches_reference_normalization(self, analyzer):
        result = analyzer.detect_stress(make_features(jitter=0.015))
        assert result["jitter_stress"] == pytest.approx(
            min(0.015 / 0.01 * 100, 100)
        )


class TestJitterImpactOnStressScore:
    """Jitter changes must move the overall stress score meaningfully."""

    def test_stress_score_responds_to_jitter(self, analyzer):
        normal = analyzer.detect_stress(make_features(jitter=0.005))
        tense = analyzer.detect_stress(make_features(jitter=0.015))
        assert tense["stress_score"] - normal["stress_score"] == pytest.approx(
            0.20 * (min(0.015 / 0.01, 1.0) - 0.005 / 0.01) * 100
        )

    def test_high_jitter_crosses_stress_threshold(self, analyzer):
        result = analyzer.detect_stress(make_features(jitter=0.02))
        assert result["stress_score"] >= analyzer.stress_threshold

    def test_extreme_jitter_pushes_toward_coercion(self, analyzer):
        result = analyzer.detect_stress(make_features(jitter=0.02, f0_mean=180.0))
        assert result["stress_score"] > analyzer.stress_threshold

    def test_low_jitter_keeps_normal_classification(self, analyzer):
        result = analyzer.detect_stress(make_features(jitter=0.001))
        assert result["classification"] == "NORMAL"


class TestJitterAgainstShimmerConsistency:
    """jitter and shimmer use the same reference-normalization scheme."""

    def test_jitter_scaling_mirrors_shimmer(self, analyzer):
        jitter = analyzer.detect_stress(make_features(jitter=0.01))
        shimmer = analyzer.detect_stress(make_features(shimmer=0.15))
        assert jitter["jitter_stress"] == pytest.approx(100.0)
        assert shimmer["shimmer_stress"] == pytest.approx(100.0)

    def test_half_reference_half_stress_for_both(self, analyzer):
        jitter = analyzer.detect_stress(make_features(jitter=0.005))
        shimmer = analyzer.detect_stress(make_features(shimmer=0.075))
        assert jitter["jitter_stress"] == pytest.approx(50.0)
        assert shimmer["shimmer_stress"] == pytest.approx(50.0)


class TestDetectStressStability:
    """Other detect_stress outputs must remain well-formed."""

    def test_score_in_unit_range(self, analyzer):
        result = analyzer.detect_stress(make_features(jitter=0.02))
        assert 0.0 <= result["stress_score"] <= 100.0

    def test_classification_is_valid(self, analyzer):
        for jitter in (0.001, 0.01, 0.05):
            classification = analyzer.detect_stress(make_features(jitter=jitter))["classification"]
            assert classification in {"NORMAL", "MILD_STRESS", "SEVERE_COERCION"}

    def test_all_indicators_present(self, analyzer):
        result = analyzer.detect_stress(make_features())
        for key in (
            "stress_score",
            "jitter_stress",
            "shimmer_stress",
            "f0_stress",
            "rate_stress",
            "prosody_stress",
            "background_stress",
            "snr_stress",
            "confidence",
            "recommended_action",
        ):
            assert key in result

    def test_confidence_bounded(self, analyzer):
        result = analyzer.detect_stress(make_features())
        assert 0.0 <= result["confidence"] <= 1.0

    def test_action_matches_classification(self, analyzer):
        normal = analyzer.detect_stress(make_features(jitter=0.001))
        assert normal["recommended_action"] == "PROCEED"

        severe = analyzer.detect_stress(
            make_features(jitter=0.02, f0_mean=200.0, speech_rate=9.0, prosody_entropy=0.5)
        )
        assert severe["classification"] == "SEVERE_COERCION"
        assert severe["recommended_action"] == "CALLBACK_REQUIRED"

    def test_custom_thresholds_respected(self, analyzer):
        custom = VoiceStressAnalyzer(stress_threshold=10.0, coercion_threshold=90.0)
        result = custom.detect_stress(make_features(jitter=0.01))
        assert result["classification"] == "MILD_STRESS"


class TestUserBaselineVariants:
    """detect_stress must honor provided and default baselines."""

    def test_default_baseline_used_without_profile(self, analyzer):
        result = analyzer.detect_stress(make_features(f0_mean=120.0))
        assert result["f0_stress"] == 0.0

    def test_user_baseline_changes_f0_stress(self, analyzer):
        baseline = {"f0_mean": 100.0, "speech_rate": 4.5}
        result = analyzer.detect_stress(make_features(f0_mean=120.0), user_baseline=baseline)
        assert result["f0_stress"] == pytest.approx(min(20.0 / 40.0 * 100, 100))

    def test_baseline_speech_rate_affects_rate_stress(self, analyzer):
        baseline = {"f0_mean": 120.0, "speech_rate": 3.0}
        result = analyzer.detect_stress(make_features(speech_rate=4.5), user_baseline=baseline)
        assert result["rate_stress"] == pytest.approx(50.0)

    def test_empty_user_baseline_falls_back(self, analyzer):
        result = analyzer.detect_stress(make_features(), user_baseline={})
        assert result["f0_stress"] == 0.0


class TestMockFeaturesPath:
    """VoiceFeatures defaults must keep detect_stress well-behaved."""

    def test_mock_features_classification(self, analyzer):
        analyzer_no_audio = VoiceStressAnalyzer()
        features = analyzer_no_audio._mock_features()
        result = analyzer.detect_stress(features)
        assert result["classification"] == "NORMAL"
        assert result["jitter_stress"] == pytest.approx(50.0)

    def test_mock_features_all_fields(self, analyzer):
        features = analyzer._mock_features()
        assert features.jitter == pytest.approx(0.005)
        assert features.shimmer == pytest.approx(0.05)
