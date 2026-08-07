"""Unit tests for the time series helper module."""

import pytest

from src.utils.time_series import (
    fill_gaps,
    first_and_last,
    moving_average,
    resample_series,
    time_bucket,
)


class TestMovingAverage:
    def test_known_values(self):
        assert moving_average([1.0, 2.0, 3.0, 4.0, 5.0], 3) == pytest.approx(
            [None, None, 2.0, 3.0, 4.0]
        )

    def test_window_one_identity(self):
        assert moving_average([1.0, 2.0, 3.0], 1) == [1.0, 2.0, 3.0]

    def test_window_padding_none(self):
        result = moving_average([10.0, 20.0, 30.0], 2)
        assert result[0] is None
        assert result[1:] == pytest.approx([15.0, 25.0])

    def test_window_equal_to_length(self):
        assert moving_average([1.0, 2.0, 3.0], 3) == pytest.approx(
            [None, None, 2.0]
        )

    def test_window_exceeds_length_all_none(self):
        assert moving_average([1.0, 2.0], 5) == [None, None]

    def test_empty_values_with_window(self):
        assert moving_average([], 3) == []

    def test_window_zero_raises(self):
        with pytest.raises(ValueError):
            moving_average([1.0, 2.0], 0)

    def test_window_negative_raises(self):
        with pytest.raises(ValueError):
            moving_average([1.0, 2.0], -2)


class TestResampleSeries:
    def test_buckets_sums_correctly(self):
        points = [(0, 1.0), (5, 2.0), (10, 4.0), (15, 8.0)]
        assert resample_series(points, 10) == {0: 3.0, 10: 12.0}

    def test_multiple_points_same_bucket(self):
        points = [(1, 1.0), (2, 2.0), (4, 3.0), (6, 4.0)]
        assert resample_series(points, 5) == {0: 6.0, 5: 4.0}

    def test_across_bucket_boundary(self):
        points = [(9, 1.0), (10, 2.0), (11, 3.0)]
        assert resample_series(points, 10) == {0: 1.0, 10: 5.0}

    def test_empty_returns_empty(self):
        assert resample_series([], 10) == {}

    def test_unsorted_points_bucket_correctly(self):
        points = [(15, 2.0), (5, 3.0), (1, 4.0)]
        assert resample_series(points, 10) == {0: 7.0, 10: 2.0}

    def test_bucket_seconds_zero_raises(self):
        with pytest.raises(ValueError):
            resample_series([(0, 1.0)], 0)

    def test_bucket_seconds_negative_raises(self):
        with pytest.raises(ValueError):
            resample_series([(0, 1.0)], -5)


class TestTimeBucket:
    def test_bucket_start_floor(self):
        assert time_bucket(17, 10) == 10
        assert time_bucket(99, 60) == 60

    def test_aligned_timestamp_unchanged(self):
        assert time_bucket(30, 10) == 30

    def test_larger_bucket_sizes(self):
        assert time_bucket(3601, 3600) == 3600

    def test_bucket_seconds_zero_raises(self):
        with pytest.raises(ValueError):
            time_bucket(10, 0)


class TestFillGaps:
    def test_fills_missing_with_default(self):
        series = {0: 1.0, 20: 3.0}
        assert fill_gaps(series, 0, 20, 10) == {0: 1.0, 10: 0.0, 20: 3.0}

    def test_preserves_existing_values(self):
        series = {0: 5.0, 10: 7.0, 20: 9.0}
        assert fill_gaps(series, 0, 20, 10) == series

    def test_steps_correctly(self):
        result = fill_gaps({}, 5, 13, 4)
        assert result == {5: 0.0, 9: 0.0, 13: 0.0}

    def test_custom_fill_value(self):
        assert fill_gaps({0: 1.0}, 0, 20, 10, fill=-1.0) == {
            0: 1.0,
            10: -1.0,
            20: -1.0,
        }

    def test_start_beyond_end_returns_empty(self):
        assert fill_gaps({1: 2.0}, 10, 5, 1) == {}

    def test_step_zero_raises(self):
        with pytest.raises(ValueError):
            fill_gaps({}, 0, 10, 0)


class TestFirstAndLast:
    def test_sorted_input(self):
        points = [(10, 1.0), (20, 2.0), (30, 3.0)]
        assert first_and_last(points) == (10, 30)

    def test_empty_returns_none_pair(self):
        assert first_and_last([]) == (None, None)

    def test_unsorted_input_sorts(self):
        points = [(30, 3.0), (10, 1.0), (20, 2.0)]
        assert first_and_last(points) == (10, 30)

    def test_single_point(self):
        assert first_and_last([(42, 1.0)]) == (42, 42)

    def test_input_not_mutated(self):
        points = [(30, 3.0), (10, 1.0)]
        first_and_last(points)
        assert points == [(30, 3.0), (10, 1.0)]
