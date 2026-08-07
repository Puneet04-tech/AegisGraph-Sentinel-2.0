"""Unit tests for src/features/statistical.py."""

import math

import pytest

from src.features.statistical import (
    coefficient_of_variation,
    count_above_threshold,
    describe_sequence,
    entropy,
    percentile,
    rolling_mean,
    zscore,
)


@pytest.mark.parametrize(
    "values,expected",
    [
        (
            [1, 2, 3, 4, 5],
            {
                "mean": 3.0,
                "median": 3.0,
                "std": math.sqrt(2),
                "min": 1.0,
                "max": 5.0,
                "sum": 15.0,
                "count": 5.0,
                "range": 4.0,
            },
        ),
        (
            [7],
            {
                "mean": 7.0,
                "median": 7.0,
                "std": 0.0,
                "min": 7.0,
                "max": 7.0,
                "sum": 7.0,
                "count": 1.0,
                "range": 0.0,
            },
        ),
        (
            [-2.0, -1.0, 0.0, 1.0, 2.0],
            {
                "mean": 0.0,
                "median": 0.0,
                "std": math.sqrt(2),
                "min": -2.0,
                "max": 2.0,
                "sum": 0.0,
                "count": 5.0,
                "range": 4.0,
            },
        ),
        (
            [1, 1, 1],
            {
                "mean": 1.0,
                "median": 1.0,
                "std": 0.0,
                "min": 1.0,
                "max": 1.0,
                "sum": 3.0,
                "count": 3.0,
                "range": 0.0,
            },
        ),
    ],
)
def test_describe_sequence(values, expected):
    result = describe_sequence(values)
    assert set(result) == set(expected)
    for key, value in expected.items():
        assert result[key] == pytest.approx(value)


def test_describe_sequence_empty_returns_zeros():
    assert describe_sequence([]) == {
        "mean": 0.0,
        "median": 0.0,
        "std": 0.0,
        "min": 0.0,
        "max": 0.0,
        "sum": 0.0,
        "count": 0.0,
        "range": 0.0,
    }


@pytest.mark.parametrize(
    "value,mean,std,expected",
    [
        (10.0, 5.0, 2.0, 2.5),
        (2.0, 5.0, 3.0, -1.0),
        (5.0, 5.0, 1.0, 0.0),
        (42.0, 42.0, 0.0, 0.0),
        (0.0, 0.0, 0.0, 0.0),
    ],
)
def test_zscore(value, mean, std, expected):
    assert zscore(value, mean, std) == pytest.approx(expected)


def test_zscore_zero_std_returns_zero():
    assert zscore(100.0, 3.0, 0.0) == 0.0


@pytest.mark.parametrize(
    "values,p,expected",
    [
        ([1, 2, 3, 4, 5], 50.0, 3.0),
        ([1, 2, 3, 4, 5], 0.0, 1.0),
        ([1, 2, 3, 4, 5], 100.0, 5.0),
        ([1, 2, 3, 4], 50.0, 2.5),
        ([10.0, 20.0, 30.0], 25.0, 15.0),
        ([1, 2, 3, 4, 5], 25.0, 2.0),
        ([1, 2, 3, 4, 5], 75.0, 4.0),
    ],
)
def test_percentile(values, p, expected):
    assert percentile(values, p) == pytest.approx(expected)


@pytest.mark.parametrize(
    "p,expected",
    [
        (-20.0, 1.0),
        (0.0, 1.0),
        (100.0, 5.0),
        (250.0, 5.0),
    ],
)
def test_percentile_clamps_out_of_range(p, expected):
    assert percentile([1, 2, 3, 4, 5], p) == pytest.approx(expected)


def test_percentile_empty_raises():
    with pytest.raises(ValueError):
        percentile([], 50.0)


@pytest.mark.parametrize(
    "values,window,expected",
    [
        ([1.0, 2.0, 3.0, 4.0], 1, [1.0, 2.0, 3.0, 4.0]),
        ([1.0, 2.0, 3.0, 4.0], 2, [1.0, 1.5, 2.5, 3.5]),
        ([1.0, 2.0, 3.0, 4.0], 4, [1.0, 1.5, 2.0, 2.5]),
        ([1.0, 2.0, 3.0], 10, [1.0, 1.5, 2.0]),
        ([5.0, 5.0, 5.0, 5.0], 3, [5.0, 5.0, 5.0, 5.0]),
        ([], 3, []),
    ],
)
def test_rolling_mean(values, window, expected):
    assert rolling_mean(values, window) == pytest.approx(expected)


def test_rolling_mean_window_zero_raises():
    with pytest.raises(ValueError):
        rolling_mean([1.0, 2.0], 0)


def test_rolling_mean_window_negative_raises():
    with pytest.raises(ValueError):
        rolling_mean([1.0, 2.0], -1)


def test_rolling_mean_never_contains_nan():
    result = rolling_mean([1.0, 2.0, 3.0, 4.0, 5.0], 3)
    assert len(result) == 5
    assert all(not math.isnan(value) for value in result)


@pytest.mark.parametrize(
    "values,expected",
    [
        ([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0], 0.4),
        ([5.0, 5.0, 5.0], 0.0),
        ([-1.0, 0.0, 1.0], 0.0),
        ([100.0, 110.0], 5.0 / 105.0),
    ],
)
def test_coefficient_of_variation(values, expected):
    assert coefficient_of_variation(values) == pytest.approx(expected)


def test_coefficient_of_variation_empty_returns_zero():
    assert coefficient_of_variation([]) == 0.0


def test_coefficient_of_variation_zero_mean_returns_zero():
    assert coefficient_of_variation([0.0, 0.0, 0.0]) == 0.0


@pytest.mark.parametrize(
    "counts,expected",
    [
        ([1.0, 1.0, 1.0, 1.0], 2.0),
        ([1.0, 1.0, 1.0], math.log2(3)),
        ([1.0, 0.0, 1.0], 1.0),
        ([1.0], 0.0),
        ([10.0], 0.0),
        ([0.0, 0.0, 0.0], 0.0),
        ([], 0.0),
    ],
)
def test_entropy(counts, expected):
    assert entropy(counts) == pytest.approx(expected)


def test_entropy_raw_counts_match_proportions():
    raw = entropy([3.0, 1.0])
    proportional = entropy([0.75, 0.25])
    assert raw == pytest.approx(proportional)


@pytest.mark.parametrize(
    "values,threshold,expected",
    [
        ([1.0, 2.0, 3.0, 4.0, 5.0], 3.0, 2),
        ([1.0, 2.0, 3.0, 4.0, 5.0], 0.0, 5),
        ([1.0, 2.0, 3.0, 4.0, 5.0], 10.0, 0),
        ([1.0, 2.0, 3.0, 4.0, 5.0], 5.0, 0),
        ([-5.0, -1.0, 0.0, 2.0], -2.0, 3),
        ([], 1.0, 0),
    ],
)
def test_count_above_threshold(values, threshold, expected):
    assert count_above_threshold(values, threshold) == expected
