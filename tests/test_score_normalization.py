"""
Regression tests for score normalization and aggregation edge cases.

Primary regression: ``ScoreCalculator.normalize_score`` raised ``ValueError``
when ``min_value == max_value`` even though the method's own guard intends to
return ``0.0`` for a degenerate range. The guard was unreachable because
``EdgeCaseHandler.safe_float`` raises for ``min_value >= max_value`` before the
equal-range check could run. The guard now runs first, so degenerate ranges
degrade gracefully instead of crashing callers.
"""

import math

import pytest

from src.scoring.score_calculator import ScoreCalculator, RiskScorer
from src.scoring.edge_cases import EdgeCaseHandler
from src.scoring.threshold_config import ThresholdConfig


class TestNormalizeScoreDegenerateRange:
    """The equal min/max range must return 0.0, not raise."""

    def test_equal_zero_range_returns_zero(self):
        assert ScoreCalculator.normalize_score(0.5, 0.0, 0.0) == 0.0

    def test_equal_nonzero_range_returns_zero(self):
        assert ScoreCalculator.normalize_score(7.0, 5.0, 5.0) == 0.0

    def test_equal_range_with_out_of_range_value_returns_zero(self):
        assert ScoreCalculator.normalize_score(-3.0, 5.0, 5.0) == 0.0

    def test_equal_range_with_invalid_value_returns_zero(self):
        assert ScoreCalculator.normalize_score("not-a-number", 2.0, 2.0) == 0.0

    def test_equal_range_with_nan_returns_zero(self):
        assert ScoreCalculator.normalize_score(float("nan"), 0.0, 0.0) == 0.0

    def test_equal_range_never_raises(self):
        # The previous behavior raised ValueError for every equal-range call.
        for value in (0.0, 0.5, 1.0, -1.0, 100.0, float("inf")):
            assert ScoreCalculator.normalize_score(value, 0.0, 0.0) == 0.0


class TestNormalizeScoreBoundedRanges:
    """Scaling and clamping behavior for non-degenerate ranges."""

    def test_default_range_passthrough(self):
        assert ScoreCalculator.normalize_score(0.0) == 0.0
        assert ScoreCalculator.normalize_score(0.5) == 0.5
        assert ScoreCalculator.normalize_score(1.0) == 1.0

    def test_bounded_scaling(self):
        assert ScoreCalculator.normalize_score(75.0, 50.0, 100.0) == pytest.approx(0.5)
        assert ScoreCalculator.normalize_score(100.0, 50.0, 100.0) == pytest.approx(1.0)
        assert ScoreCalculator.normalize_score(50.0, 50.0, 100.0) == pytest.approx(0.0)

    def test_below_range_clamped_to_zero(self):
        assert ScoreCalculator.normalize_score(-5.0, 0.0, 10.0) == 0.0

    def test_above_range_clamped_to_one(self):
        assert ScoreCalculator.normalize_score(15.0, 0.0, 10.0) == 1.0

    def test_negative_range_handled(self):
        assert ScoreCalculator.normalize_score(0.0, -10.0, 10.0) == pytest.approx(0.5)

    def test_non_numeric_value_uses_min_as_default(self):
        assert ScoreCalculator.normalize_score("nope", 3.0, 7.0) == 0.0
        assert ScoreCalculator.normalize_score(None, 3.0, 7.0) == 0.0

    def test_nan_and_inf_clamp_to_min(self):
        assert ScoreCalculator.normalize_score(float("nan"), 0.0, 1.0) == 0.0
        assert ScoreCalculator.normalize_score(float("inf"), 0.0, 1.0) == 0.0
        assert ScoreCalculator.normalize_score(float("-inf"), 0.0, 1.0) == 0.0

    def test_inverted_range_still_raises(self):
        with pytest.raises(ValueError):
            ScoreCalculator.normalize_score(0.5, 10.0, 0.0)


class TestSafeFloatContract:
    """EdgeCaseHandler.safe_float refuses degenerate ranges."""

    def test_equal_range_raises(self):
        with pytest.raises(ValueError):
            EdgeCaseHandler.safe_float(0.5, min_value=0.0, max_value=0.0)

    def test_inverted_range_raises(self):
        with pytest.raises(ValueError):
            EdgeCaseHandler.safe_float(0.5, min_value=1.0, max_value=0.0)

    def test_valid_range_clamps(self):
        assert EdgeCaseHandler.safe_float(0.5, min_value=0.0, max_value=1.0) == 0.5
        assert EdgeCaseHandler.safe_float(2.0, min_value=0.0, max_value=1.0) == 1.0
        assert EdgeCaseHandler.safe_float(-1.0, min_value=0.0, max_value=1.0) == 0.0


class TestAggregateScores:
    """Weight handling in score aggregation."""

    def test_single_component_with_weight(self):
        result = ScoreCalculator.aggregate_scores({"graph": 0.8}, {"graph": 1.0})
        assert result == pytest.approx(0.8)

    def test_equal_weights_when_none_given(self):
        result = ScoreCalculator.aggregate_scores({"a": 0.2, "b": 0.8})
        assert result == pytest.approx(0.5)

    def test_weight_sum_greater_than_one_is_normalized(self):
        result = ScoreCalculator.aggregate_scores(
            {"a": 0.5, "b": 0.5}, {"a": 3.0, "b": 1.0}
        )
        # Weights 0.75 / 0.25
        assert result == pytest.approx(0.5)

    def test_zero_scores_stay_zero(self):
        result = ScoreCalculator.aggregate_scores({"a": 0.0, "b": 0.0}, {"a": 1.0, "b": 1.0})
        assert result == 0.0

    def test_empty_components_give_zero(self):
        assert ScoreCalculator.aggregate_scores({}) == 0.0

    def test_extra_weights_are_ignored(self):
        result = ScoreCalculator.aggregate_scores({"a": 1.0}, {"a": 1.0, "ghost": 9.0})
        assert result == pytest.approx(1.0)


class TestComputeConfidence:
    """Confidence bounds and determinism."""

    def test_no_breakdown_returns_overall(self):
        assert ScoreCalculator.compute_confidence(0.75) == pytest.approx(0.75)

    def test_empty_breakdown_returns_overall(self):
        assert ScoreCalculator.compute_confidence(0.6, {}) == pytest.approx(0.6)

    def test_confidence_within_unit_bounds(self):
        for overall in (0.0, 0.25, 0.5, 0.75, 1.0):
            confidence = ScoreCalculator.compute_confidence(
                overall, {"g": overall, "v": overall}
            )
            assert 0.0 <= confidence <= 1.0

    def test_confidence_is_deterministic(self):
        breakdown = {"graph": 0.8, "velocity": 0.6, "behaviour": 0.7}
        assert ScoreCalculator.compute_confidence(0.7, breakdown) == pytest.approx(
            ScoreCalculator.compute_confidence(0.7, breakdown)
        )

    def test_nan_overall_stays_bounded(self):
        confidence = ScoreCalculator.compute_confidence(float("nan"), {"g": 0.5})
        assert 0.0 <= confidence <= 1.0


class TestRiskScorerAssess:
    """End-to-end assessment with normalized components."""

    @pytest.fixture
    def scorer(self):
        return RiskScorer()

    def test_assess_returns_bounded_breakdown(self, scorer):
        assessment = scorer.assess({"graph": 0.9, "velocity": 0.8})
        assert 0.0 <= assessment.overall_score <= 1.0
        assert 0.0 <= assessment.confidence <= 1.0
        assert set(assessment.breakdown.components) == {"graph", "velocity"}

    def test_assess_block_decision(self, scorer):
        assessment = scorer.assess({"graph": 0.95})
        assert assessment.decision == "BLOCK"

    def test_assess_allow_decision(self, scorer):
        assessment = scorer.assess({"graph": 0.05})
        assert assessment.decision == "ALLOW"

    def test_assess_with_component_weights_fills_defaults(self):
        scorer = RiskScorer(component_weights={"graph": 0.6, "velocity": 0.4})
        assessment = scorer.assess({"graph": 1.0})
        # velocity missing -> default 0.5
        assert assessment.breakdown.components["velocity"] == 0.5
        assert assessment.overall_score == pytest.approx(0.8)

    def test_assess_circular_transfers_reduce_confidence(self):
        transactions = [
            {"source_account": "A", "target_account": "B"},
            {"source_account": "B", "target_account": "A"},
        ]
        without = scorer = RiskScorer().assess({"graph": 0.8})
        with_cycle = RiskScorer().assess(
            {"graph": 0.8}, metadata={"transactions": transactions}
        )
        assert with_cycle.confidence < without.confidence

    def test_assess_metadata_passthrough(self, scorer):
        assessment = scorer.assess(
            {"graph": 0.8}, metadata={"analyst": "a-1"}
        )
        assert assessment.metadata["analyst"] == "a-1"


class TestThresholdConfigInterplay:
    """Threshold config stays valid alongside degenerate normalization."""

    def test_default_thresholds(self):
        config = ThresholdConfig()
        assert config.decision_for_score(0.0) == "ALLOW"
        assert config.decision_for_score(0.6) == "REVIEW"
        assert config.decision_for_score(0.9) == "BLOCK"

    def test_normalized_score_feeds_decisions(self):
        config = ThresholdConfig()
        score = ScoreCalculator.normalize_score(0.0, 0.0, 0.0)
        assert config.decision_for_score(score) == "ALLOW"

    def test_bounded_score_feeds_decisions(self):
        config = ThresholdConfig()
        score = ScoreCalculator.normalize_score(95.0, 0.0, 100.0)
        assert config.decision_for_score(score) == "BLOCK"
