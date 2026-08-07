"""Unit tests for the streaming rolling statistics module."""

import time

import pytest

from src.utils.rolling_stats import RollingStats


def make_clock(start=100.0):
    now = [start]

    def clock():
        return now[0]

    clock.advance = lambda delta: now.__setitem__(0, now[0] + delta)
    return clock


class TestRollingStatsBasic:
    def test_add_and_count(self):
        rs = RollingStats(10.0)
        rs.add(1.0)
        rs.add(2.5)
        rs.add(-3.0)
        assert rs.count() == 3

    def test_add_accepts_explicit_timestamp(self):
        clock = make_clock()
        rs = RollingStats(10.0, clock=clock)
        rs.add(1.0, timestamp=95.0)
        rs.add(2.0, timestamp=96.0)
        assert rs.count() == 2

    def test_init_rejects_non_positive_window(self):
        with pytest.raises(ValueError):
            RollingStats(0)

    def test_injects_clock_for_testability(self):
        rs = RollingStats(10.0, clock=lambda: 50.0)
        rs.add(1.0)
        assert rs.count() == 1


class TestRollingStatsAggregates:
    def test_mean_sum_min_max(self):
        rs = RollingStats(60.0)
        for v in (10.0, 20.0, 30.0):
            rs.add(v)
        assert rs.sum() == pytest.approx(60.0)
        assert rs.mean() == pytest.approx(20.0)
        assert rs.min() == 10.0
        assert rs.max() == 30.0

    def test_variance_and_std_known_dataset(self):
        rs = RollingStats(60.0)
        for v in (2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0):
            rs.add(v)
        assert rs.variance() == pytest.approx(4.0)
        assert rs.std() == pytest.approx(2.0)

    def test_single_value_has_zero_variance(self):
        rs = RollingStats(60.0)
        rs.add(42.0)
        assert rs.variance() == 0.0
        assert rs.std() == 0.0

    def test_p95_known_dataset(self):
        rs = RollingStats(60.0)
        for v in range(1, 101):
            rs.add(float(v))
        assert rs.p95() == pytest.approx(95.0)


class TestRollingStatsWindowPruning:
    def test_old_values_dropped_from_count(self):
        clock = make_clock()
        rs = RollingStats(10.0, clock=clock)
        rs.add(1.0)
        rs.add(2.0)
        clock.advance(11.0)
        assert rs.count() == 0

    def test_partial_prune_keeps_fresh_values(self):
        clock = make_clock()
        rs = RollingStats(10.0, clock=clock)
        rs.add(1.0)
        clock.advance(6.0)
        rs.add(2.0)
        clock.advance(6.0)
        assert rs.count() == 1
        assert rs.mean() == pytest.approx(2.0)

    def test_explicit_timestamps_pruned_correctly(self):
        clock = make_clock()
        rs = RollingStats(10.0, clock=clock)
        rs.add(1.0, timestamp=100.0)
        rs.add(2.0, timestamp=105.0)
        rs.add(3.0, timestamp=112.0)
        assert rs.count() == 2
        assert rs.mean() == pytest.approx(2.5)


class TestRollingStatsEmptyWindow:
    def test_empty_window_documented_defaults(self):
        rs = RollingStats(10.0)
        assert rs.count() == 0
        assert rs.sum() == 0.0
        assert rs.mean() is None
        assert rs.min() is None
        assert rs.max() is None
        assert rs.variance() == 0.0
        assert rs.std() == 0.0
        assert rs.p95() is None
        assert rs.rate() == 0.0

    def test_empty_after_all_values_expire(self):
        clock = make_clock()
        rs = RollingStats(5.0, clock=clock)
        rs.add(1.0)
        clock.advance(6.0)
        assert rs.mean() is None
        assert rs.count() == 0


class TestRollingStatsRate:
    def test_rate_counts_per_elapsed_second(self):
        clock = make_clock()
        rs = RollingStats(60.0, clock=clock)
        for _ in range(5):
            rs.add(1.0)
            clock.advance(1.0)
        assert rs.rate() == pytest.approx(1.0)

    def test_rate_uses_first_value_timestamp(self):
        clock = make_clock()
        rs = RollingStats(60.0, clock=clock)
        rs.add(1.0)
        clock.advance(2.0)
        for _ in range(3):
            rs.add(1.0)
        assert rs.rate() == pytest.approx(2.0)

    def test_rate_guard_no_elapsed_time(self):
        rs = RollingStats(10.0, clock=lambda: 5.0)
        rs.add(1.0)
        assert rs.rate() == 0.0

    def test_rate_zero_after_window_fully_expired(self):
        clock = make_clock()
        rs = RollingStats(10.0, clock=clock)
        rs.add(1.0)
        clock.advance(10.0)
        assert rs.rate() == 0.0


class TestRollingStatsReset:
    def test_reset_clears_window(self):
        rs = RollingStats(10.0)
        rs.add(1.0)
        rs.add(2.0)
        rs.reset()
        assert rs.count() == 0
        assert rs.sum() == 0.0

    def test_reset_allows_reuse(self):
        rs = RollingStats(10.0)
        rs.add(5.0)
        rs.reset()
        rs.add(7.0)
        assert rs.mean() == pytest.approx(7.0)


class TestRollingStatsUnorderedTimestamps:
    def test_p95_ignores_timestamp_order(self):
        clock = make_clock()
        rs = RollingStats(60.0, clock=clock)
        for v in range(100, 0, -1):
            rs.add(float(v), timestamp=clock())
        assert rs.p95() == pytest.approx(95.0)
        assert rs.max() == 100.0
        assert rs.min() == 1.0
        assert rs.count() == 100


class TestRollingStatsRealClock:
    def test_values_expire_with_real_time(self):
        rs = RollingStats(0.05)
        rs.add(1.0)
        assert rs.count() == 1
        time.sleep(0.1)
        assert rs.count() == 0
        assert rs.mean() is None
        assert rs.rate() == 0.0
