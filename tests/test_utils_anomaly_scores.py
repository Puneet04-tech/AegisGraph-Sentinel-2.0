"""Unit tests for statistical anomaly scoring helpers."""

import pytest

from src.utils.anomaly_scores import (
    iqr_bounds,
    iqr_outlier,
    mad_median,
    percentile_score,
    score_anomalies,
    zscore_outlier,
)


class TestZscoreOutlier:
    def test_beyond_threshold_is_outlier(self):
        assert zscore_outlier(30.1, 0.0, 10.0) is True

    def test_at_threshold_is_not_outlier(self):
        assert zscore_outlier(30.0, 0.0, 10.0) is False

    def test_within_threshold_is_not_outlier(self):
        assert zscore_outlier(5.0, 0.0, 10.0) is False

    def test_custom_threshold(self):
        assert zscore_outlier(21.0, 0.0, 10.0, z_threshold=2.0) is True
        assert zscore_outlier(20.0, 0.0, 10.0, z_threshold=2.0) is False

    def test_zero_std_never_outlier(self):
        assert zscore_outlier(100.0, 10.0, 0.0) is False

    def test_none_value_not_outlier(self):
        assert zscore_outlier(None, 10.0, 2.0) is False
        assert zscore_outlier(5.0, None, 2.0) is False


class TestIqrBounds:
    def test_known_dataset(self):
        values = [7, 15, 36, 39, 40, 41]
        lower, upper = iqr_bounds(values)
        assert lower == pytest.approx(-22.5)
        assert upper == pytest.approx(77.5)

    def test_unsorted_input_same_result(self):
        lower, upper = iqr_bounds([41, 7, 36, 40, 15, 39])
        assert lower == pytest.approx(-22.5)
        assert upper == pytest.approx(77.5)

    def test_empty_returns_none(self):
        assert iqr_bounds([]) == (None, None)

    def test_fewer_than_four_values_returns_none(self):
        assert iqr_bounds([1]) == (None, None)
        assert iqr_bounds([1, 2, 3]) == (None, None)

    def test_exactly_four_values(self):
        lower, upper = iqr_bounds([1, 2, 3, 4])
        assert lower == pytest.approx(-1.5)
        assert upper == pytest.approx(6.5)


class TestIqrOutlier:
    def test_above_upper_bound(self):
        assert iqr_outlier(100.0, -22.5, 77.5) is True

    def test_below_lower_bound(self):
        assert iqr_outlier(-100.0, -22.5, 77.5) is True

    def test_within_bounds_not_outlier(self):
        assert iqr_outlier(0.0, -22.5, 77.5) is False
        assert iqr_outlier(50.0, -22.5, 77.5) is False

    def test_on_boundary_not_outlier(self):
        assert iqr_outlier(77.5, -22.5, 77.5) is False

    def test_none_bounds_not_outlier(self):
        assert iqr_outlier(100.0, None, None) is False


class TestPercentileScore:
    def test_max_value_is_100(self):
        assert percentile_score(100, list(range(1, 101))) == 100.0

    def test_min_value_is_near_zero(self):
        assert percentile_score(1, list(range(1, 101))) == 1.0

    def test_median_is_around_50(self):
        assert percentile_score(50, list(range(1, 101))) == 50.0

    def test_empty_returns_zero(self):
        assert percentile_score(5.0, []) == 0.0


class TestMadMedian:
    def test_known_values(self):
        median, mad = mad_median([1, 1, 2, 2, 4, 6, 9])
        assert median == pytest.approx(2.0)
        assert mad == pytest.approx(1.0)

    def test_empty_returns_zeros(self):
        assert mad_median([]) == (0.0, 0.0)


class TestScoreAnomalies:
    def test_zscore_detects_injected_outlier(self):
        values = [10.0] * 20 + [1000.0]
        scores = score_anomalies(values)
        assert 20 in scores
        assert scores[20] > 3.0
        assert all(index not in scores for index in range(20))

    def test_iqr_detects_outlier(self):
        values = [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 200]
        scores = score_anomalies(values, method="iqr")
        assert 11 in scores
        assert scores[11] == pytest.approx(200.0 - 27.5)
        assert all(index not in scores for index in range(11))

    def test_empty_returns_empty(self):
        assert score_anomalies([]) == {}
        assert score_anomalies([], method="iqr") == {}

    def test_constant_values_have_no_anomalies(self):
        assert score_anomalies([5.0] * 10) == {}
        assert score_anomalies([5.0] * 10, method="iqr") == {}

    def test_unknown_method_raises(self):
        with pytest.raises(ValueError):
            score_anomalies([1.0, 2.0, 3.0], method="bogus")
