import asyncio
import time

import pytest

from src.observability.timing_utils import (
    Stopwatch,
    elapsed,
    measure,
    quantile_sorted,
    rate_tracker,
)


class TestElapsed:
    def test_returns_positive_float_matching_sleep(self):
        start = time.perf_counter_ns()
        time.sleep(0.01)
        result = elapsed(start)
        assert isinstance(result, float)
        assert result > 0
        assert result == pytest.approx(0.01, rel=0.5)

    def test_returns_zero_for_future_start(self):
        start = time.perf_counter_ns() + 10 ** 9
        assert elapsed(start) == 0.0


class TestStopwatch:
    def test_context_manager_sets_elapsed_seconds(self):
        with Stopwatch() as sw:
            time.sleep(0.01)
        assert sw.elapsed_seconds >= 0
        assert sw.elapsed_seconds > 0
        assert sw.elapsed_seconds == pytest.approx(0.01, rel=0.5)

    def test_context_manager_returns_stopwatch(self):
        with Stopwatch() as sw:
            assert isinstance(sw, Stopwatch)

    def test_manual_start_stop(self):
        sw = Stopwatch()
        sw.start()
        time.sleep(0.01)
        result = sw.stop()
        assert result == sw.elapsed_seconds
        assert result > 0

    def test_stop_before_start_returns_zero(self):
        sw = Stopwatch()
        assert sw.stop() == 0.0
        assert sw.elapsed_seconds == 0.0

    def test_reset_clears_elapsed(self):
        sw = Stopwatch()
        sw.start()
        time.sleep(0.005)
        sw.stop()
        assert sw.elapsed_seconds > 0
        sw.reset()
        assert sw.elapsed_seconds == 0.0

    def test_reset_allows_reuse(self):
        sw = Stopwatch()
        with sw:
            time.sleep(0.005)
        first = sw.elapsed_seconds
        sw.reset()
        with sw:
            time.sleep(0.005)
        assert sw.elapsed_seconds > 0
        assert sw.elapsed_seconds == pytest.approx(first, rel=0.5)


class TestMeasure:
    def test_sync_sink_receives_label_and_seconds_return_unchanged(self):
        calls = []

        @measure("sync-op", sink=lambda label, seconds: calls.append((label, seconds)))
        def do_work(x):
            time.sleep(0.005)
            return x * 2

        assert do_work(21) == 42
        assert len(calls) == 1
        label, seconds = calls[0]
        assert label == "sync-op"
        assert isinstance(seconds, float)
        assert seconds > 0

    def test_sync_without_sink_does_not_raise(self):
        @measure("bare")
        def do_work():
            return "ok"

        assert do_work() == "ok"

    def test_async_sink_called_and_result_unchanged(self):
        calls = []

        @measure("async-op", sink=lambda label, seconds: calls.append((label, seconds)))
        async def do_work(x):
            await asyncio.sleep(0.005)
            return x + 1

        assert asyncio.run(do_work(1)) == 2
        assert len(calls) == 1
        label, seconds = calls[0]
        assert label == "async-op"
        assert seconds > 0

    def test_async_without_sink_does_not_raise(self):
        @measure("bare-async")
        async def do_work():
            return "async-ok"

        assert asyncio.run(do_work()) == "async-ok"

    def test_measure_preserves_original_name(self):
        @measure("named")
        def do_work():
            pass

        assert do_work.__name__ == "do_work"


class TestRateTracker:
    def test_empty_stats_are_zeros(self):
        track = rate_tracker()
        stats = track.stats()
        assert stats == {"count": 0, "sum": 0.0, "mean": 0.0, "window_seconds": 0.0}

    def test_count_sum_mean(self):
        track = rate_tracker()
        for value in (1, 2, 3, 4):
            track(value)
        stats = track.stats()
        assert stats["count"] == 4
        assert stats["sum"] == 10
        assert stats["mean"] == 2.5

    def test_window_seconds_reflects_span(self):
        track = rate_tracker()
        track(1)
        time.sleep(0.02)
        track(2)
        time.sleep(0.02)
        track(3)
        window = track.stats()["window_seconds"]
        assert window > 0
        assert window == pytest.approx(0.04, rel=0.5)

    def test_single_track_window_is_zero(self):
        track = rate_tracker()
        track(5)
        assert track.stats()["window_seconds"] == 0.0
        assert track.stats()["mean"] == 5.0


class TestQuantileSorted:
    def test_median_odd_count(self):
        values = [5, 1, 3, 2, 4]
        assert quantile_sorted(values, 0.5) == 3

    def test_median_even_count(self):
        values = [4, 1, 3, 2]
        assert quantile_sorted(values, 0.5) == 2

    def test_min_and_max(self):
        values = [7, 2, 9, 1, 4]
        assert quantile_sorted(values, 0.0) == 1
        assert quantile_sorted(values, 1.0) == 9

    def test_q_is_clamped(self):
        values = [7, 2, 9, 1, 4]
        assert quantile_sorted(values, -1.0) == 1
        assert quantile_sorted(values, 2.0) == 9

    def test_empty_returns_none(self):
        assert quantile_sorted([], 0.5) is None

    def test_does_not_mutate_input_order(self):
        values = [5, 1, 3]
        original = values.copy()
        quantile_sorted(values, 0.5)
        assert values == original
