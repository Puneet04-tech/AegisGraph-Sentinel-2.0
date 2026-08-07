"""Unit tests for src/features/statistical_aggregations.py.

These helpers produce the raw aggregations (z-scores, scaling, bins,
summaries) that downstream behavior/velocity feature builders consume, so the
tests pin both the happy-path numerics and every degenerate-input guard.
"""

import math

from src.features.statistical_aggregations import (
    binned,
    clip,
    max_min,
    mean_std,
    min_max_scale,
    ratio,
    summarize_features,
    zscore,
)


def test_zscore_standard_result():
    assert math.isclose(zscore(10.0, 5.0, 2.0), 2.5)
    assert math.isclose(zscore(5.0, 5.0, 2.0), 0.0)
    assert math.isclose(zscore(0.0, 5.0, 2.0), -2.5)


def test_zscore_zero_std_guard():
    assert zscore(10.0, 5.0, 0.0) == 0.0
    assert zscore(-3.0, 1.0, 0) == 0.0


def test_zscore_none_guard():
    assert zscore(None, 5.0, 2.0) == 0.0
    assert zscore(10.0, None, 2.0) == 0.0
    assert zscore(10.0, 5.0, None) == 0.0


def test_min_max_scale_bounds():
    assert min_max_scale(0.0, 0.0, 10.0) == 0.0
    assert min_max_scale(5.0, 0.0, 10.0) == 0.5
    assert min_max_scale(10.0, 0.0, 10.0) == 1.0


def test_min_max_scale_equal_bounds_guard():
    assert min_max_scale(7.0, 7.0, 7.0) == 1.0
    assert min_max_scale(3.0, 7.0, 7.0) == 0.0


def test_min_max_scale_none_guard():
    assert min_max_scale(None, 0.0, 10.0) == 0.0
    assert min_max_scale(5.0, None, 10.0) == 0.0
    assert min_max_scale(5.0, 0.0, None) == 0.0


def test_clip_boundaries():
    assert clip(5.0, 0.0, 10.0) == 5.0
    assert clip(0.0, 0.0, 10.0) == 0.0
    assert clip(10.0, 0.0, 10.0) == 10.0


def test_clip_clamps_out_of_range():
    assert clip(-5.0, 0.0, 10.0) == 0.0
    assert clip(15.0, 0.0, 10.0) == 10.0


def test_clip_none_returns_zero():
    assert clip(None, 0.0, 10.0) == 0.0


def test_binned_within_edges():
    assert binned(5.0, [0.0, 5.0, 10.0]) == 1
    assert binned(10.0, [0.0, 5.0, 10.0]) == 2


def test_binned_below_first_edge():
    assert binned(-1.0, [0.0, 5.0, 10.0]) == 0


def test_binned_above_last_edge():
    assert binned(15.0, [0.0, 5.0, 10.0]) == 3


def test_binned_none_or_empty_edges():
    assert binned(None, [0.0, 5.0]) == -1
    assert binned(3.0, []) == -1


def test_binned_unsorted_edges_sorted_before_search():
    assert binned(5.0, [10.0, 0.0, 5.0]) == 1


def test_ratio_normal():
    assert ratio(10.0, 5.0) == 2.0
    assert ratio(3.0, 4.0) == 0.75


def test_ratio_zero_denominator_returns_none():
    assert ratio(10.0, 0.0) is None
    assert ratio(0.0, 0) is None


def test_ratio_none_inputs():
    assert ratio(None, 5.0) is None
    assert ratio(10.0, None) is None
    assert ratio(None, None) is None


def test_mean_std_known_values():
    mean, std = mean_std([10.0, 12.0, 23.0, 23.0, 16.0])
    assert math.isclose(mean, 16.8)
    assert math.isclose(std, math.sqrt(146.8 / 5))


def test_mean_std_empty():
    assert mean_std([]) == (0.0, 0.0)
    assert mean_std([None, None]) == (0.0, 0.0)


def test_max_min_known_values():
    assert max_min([3.0, 9.0, 1.0, 7.0]) == (9.0, 1.0)
    assert max_min([5.0]) == (5.0, 5.0)


def test_max_min_empty():
    assert max_min([]) == (0.0, 0.0)
    assert max_min([None, None]) == (0.0, 0.0)


def test_summarize_features_full_dict():
    result = summarize_features([10.0, 12.0, 23.0, 23.0, 16.0])
    assert result["count"] == 5
    assert result["sum"] == 84.0
    assert math.isclose(result["mean"], 16.8)
    assert result["min"] == 10.0
    assert result["max"] == 23.0
    assert math.isclose(result["std"], math.sqrt(146.8 / 5))


def test_summarize_features_empty():
    assert summarize_features([]) == {
        "count": 0.0,
        "sum": 0.0,
        "mean": 0.0,
        "min": 0.0,
        "max": 0.0,
        "std": 0.0,
    }


def test_summarize_features_with_edges_bins_sum_to_count():
    result = summarize_features([1.0, 4.0, 7.0, 10.0, 13.0], edges=[3.0, 6.0, 9.0, 12.0])
    assert result["count"] == 5
    assert sum(result["bins"].values()) == result["count"]
    assert result["bins"][0] == 1
    assert result["bins"][1] == 1
    assert result["bins"][4] == 1


def test_summarize_features_none_values_filtered():
    result = summarize_features([10.0, None, 12.0, None, 23.0], edges=[10.0, 20.0])
    assert result["count"] == 3
    assert result["sum"] == 45.0
    assert sum(result["bins"].values()) == 3
    assert result["bins"][0] == 1
    assert result["bins"][1] == 1
    assert result["bins"][2] == 1
