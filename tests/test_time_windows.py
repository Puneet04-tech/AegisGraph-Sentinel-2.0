"""Tests for src.utils.time_windows."""

import pytest

from src.utils.time_windows import (
    bucket_index,
    bucket_start,
    group_by_window,
    iter_windows,
    rolling_window_count,
)


@pytest.mark.parametrize(
    ("ts", "window", "expected"),
    [
        (100.0, 30.0, 90.0),
        (0.0, 30.0, 0.0),
        (30.0, 30.0, 30.0),
        (45.0, 30.0, 30.0),
        (29.999, 30.0, 0.0),
        (59.0, 30.0, 30.0),
        (100.0, 60.0, 60.0),
        (123.456, 10.0, 120.0),
        (-1.0, 30.0, -30.0),
        (-30.0, 30.0, -30.0),
        (-45.0, 30.0, -60.0),
        (-0.001, 30.0, -30.0),
        (100.0, 0.5, 100.0),
        (100.4, 0.5, 100.0),
    ],
)
def test_bucket_start(ts, window, expected):
    assert bucket_start(ts, window) == expected


def test_bucket_start_returns_boundary_multiple():
    for ts in (0.0, 7.0, 30.0, 60.0, 90.0, 100.0):
        start = bucket_start(ts, 30.0)
        assert start % 30.0 == 0
        assert start <= ts


def test_bucket_start_invalid_window():
    for window in (0.0, -5.0):
        with pytest.raises(ValueError):
            bucket_start(0.0, window)


@pytest.mark.parametrize(
    ("ts", "window", "expected"),
    [
        (100.0, 30.0, 3),
        (0.0, 30.0, 0),
        (29.0, 30.0, 0),
        (30.0, 30.0, 1),
        (-1.0, 30.0, -1),
        (-31.0, 30.0, -2),
    ],
)
def test_bucket_index(ts, window, expected):
    assert bucket_index(ts, window) == expected


@pytest.mark.parametrize(
    ("ts", "window", "epoch", "expected"),
    [
        (100.0, 30.0, 10.0, 3),
        (10.0, 30.0, 10.0, 0),
        (0.0, 30.0, 10.0, -1),
        (40.0, 30.0, 10.0, 1),
    ],
)
def test_bucket_index_with_epoch(ts, window, epoch, expected):
    assert bucket_index(ts, window, epoch) == expected


@pytest.mark.parametrize(
    ("ts", "window", "epoch"),
    [
        (0.0, 30.0, 0.0),
        (100.0, 30.0, 0.0),
        (123.0, 7.0, 0.0),
        (40.0, 30.0, 10.0),
        (-55.0, 30.0, 10.0),
        (-0.001, 30.0, 0.0),
    ],
)
def test_bucket_index_consistent_with_bucket_start(ts, window, epoch):
    idx = bucket_index(ts, window, epoch)
    assert idx * window == bucket_start(ts - epoch, window)
    assert epoch + idx * window <= ts
    assert epoch + (idx + 1) * window > ts


def test_bucket_index_invalid_window():
    with pytest.raises(ValueError):
        bucket_index(0.0, 0.0)


def test_iter_windows_covers_range():
    windows = list(iter_windows(95.0, 185.0, 30.0))
    assert windows == [
        (90.0, 120.0),
        (120.0, 150.0),
        (150.0, 180.0),
        (180.0, 210.0),
    ]
    assert windows[0][0] <= 95.0
    assert windows[-1][1] >= 185.0


def test_iter_windows_non_overlapping_contiguous():
    windows = list(iter_windows(0.0, 100.0, 10.0))
    for (start_a, end_a), (start_b, end_b) in zip(windows, windows[1:]):
        assert end_a == start_b
    assert windows[0][0] == 0.0
    assert windows[-1][1] == 100.0


@pytest.mark.parametrize(
    ("start", "end", "window", "expected"),
    [
        (0.0, 90.0, 30.0, [(0.0, 30.0), (30.0, 60.0), (60.0, 90.0)]),
        (0.0, 91.0, 30.0, [(0.0, 30.0), (30.0, 60.0), (60.0, 90.0), (90.0, 120.0)]),
        (1.0, 31.0, 30.0, [(0.0, 30.0), (30.0, 60.0)]),
        (30.0, 60.0, 30.0, [(30.0, 60.0)]),
    ],
)
def test_iter_windows_boundaries(start, end, window, expected):
    assert list(iter_windows(start, end, window)) == expected


def test_iter_windows_zero_length_range():
    assert list(iter_windows(100.0, 100.0, 30.0)) == []
    assert list(iter_windows(0.0, 0.0, 0.5)) == []


def test_iter_windows_negative_timestamps():
    windows = list(iter_windows(-45.0, -1.0, 30.0))
    assert windows == [(-60.0, -30.0), (-30.0, 0.0)]


def test_iter_windows_reversed_range_raises():
    with pytest.raises(ValueError):
        list(iter_windows(60.0, 0.0, 30.0))


def test_iter_windows_invalid_window():
    with pytest.raises(ValueError):
        list(iter_windows(0.0, 60.0, 0.0))


def test_group_by_window_groups_by_bucket():
    items = [
        {"id": "a", "timestamp": 5.0},
        {"id": "b", "timestamp": 25.0},
        {"id": "c", "timestamp": 35.0},
        {"id": "d", "timestamp": 70.0},
    ]
    groups = group_by_window(items, 30.0)
    assert set(groups) == {0, 1, 2}
    assert [i["id"] for i in groups[0]] == ["a", "b"]
    assert [i["id"] for i in groups[1]] == ["c"]
    assert [i["id"] for i in groups[2]] == ["d"]


def test_group_by_window_preserves_order_within_bucket():
    items = [{"id": i, "timestamp": 1.0} for i in range(10)]
    groups = group_by_window(items, 30.0)
    assert [i["id"] for i in groups[0]] == list(range(10))


def test_group_by_window_custom_key():
    items = [
        {"id": "x", "ts": 10.0},
        {"id": "y", "ts": 40.0},
    ]
    groups = group_by_window(items, 30.0, ts_key="ts")
    assert set(groups) == {0, 1}


def test_group_by_window_negative_timestamps():
    items = [{"id": "a", "timestamp": -10.0}, {"id": "b", "timestamp": -40.0}]
    groups = group_by_window(items, 30.0)
    assert set(groups) == {-1, -2}


def test_group_by_window_missing_key_raises():
    with pytest.raises(KeyError):
        group_by_window([{"id": "a"}], 30.0)
    with pytest.raises(KeyError):
        group_by_window([{"timestamp": 1.0}, {"id": "b"}], 30.0)


def test_group_by_window_empty():
    assert group_by_window([], 30.0) == {}


def test_group_by_window_invalid_window():
    with pytest.raises(ValueError):
        group_by_window([{"timestamp": 1.0}], 0.0)


@pytest.mark.parametrize(
    ("timestamps", "window", "expected"),
    [
        ([1.0, 2.0, 3.0], 1.0, [1, 2, 2]),
        ([], 1.0, []),
        ([1.0, 1.5, 2.0, 2.5], 1.0, [1, 2, 3, 3]),
        ([5.0, 5.0, 5.0], 1.0, [3, 3, 3]),
        ([42.0, 42.0, 42.0], 100.0, [3, 3, 3]),
        ([100.0, 101.0, 102.0], 10.0, [1, 2, 3]),
        ([10.0, 11.0, 12.0], 100.0, [1, 2, 3]),
        ([1.0], 0.5, [1]),
        ([0.0, 100.0, 200.0], 1.0, [1, 1, 1]),
        ([3.0, 1.0, 2.0], 1.0, [2, 1, 2]),
    ],
)
def test_rolling_window_count(timestamps, window, expected):
    assert rolling_window_count(timestamps, window) == expected


def test_rolling_window_count_out_of_order_consistent_with_sorted():
    timestamps = [10.0, 11.0, 10.5, 20.0, 10.2, 9.9]
    result = rolling_window_count(timestamps, 1.0)
    for ts, count in zip(timestamps, result):
        manual = sum(1 for t in timestamps if ts - 1.0 <= t <= ts)
        assert count == manual


def test_rolling_window_count_inclusive_boundaries():
    assert rolling_window_count([0.0, 1.0], 1.0) == [1, 2]
    assert rolling_window_count([0.0, 1.0001], 1.0) == [1, 1]


def test_rolling_window_count_invalid_window():
    with pytest.raises(ValueError):
        rolling_window_count([1.0], 0.0)
