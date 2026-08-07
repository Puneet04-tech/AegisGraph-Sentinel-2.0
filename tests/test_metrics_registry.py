"""Unit tests for src/observability/metrics_registry.py."""

import asyncio
import threading
import time

import pytest

from src.observability.metrics_registry import (
    MetricsRegistry,
    metrics_registry,
    timed,
)


@pytest.fixture
def registry():
    return MetricsRegistry()


@pytest.fixture(autouse=True)
def _reset_global_registry():
    metrics_registry.reset()
    yield
    metrics_registry.reset()


def test_counter_increments_and_unknown_counter_is_zero(registry):
    assert registry.get_counter("requests") == 0
    registry.counter("requests")
    registry.counter("requests")
    assert registry.get_counter("requests") == 2


def test_counter_with_explicit_delta(registry):
    registry.counter("balance", 5)
    registry.counter("balance", -2)
    assert registry.get_counter("balance") == 3


def test_counter_unknown_returns_zero_without_creation(registry):
    assert registry.get_counter("missing") == 0
    assert registry.snapshot()["counters"] == {}


def test_gauge_set_and_read(registry):
    assert registry.get_gauge("workers") == 0
    registry.gauge("workers", 42.5)
    registry.gauge("workers", 7)
    assert registry.get_gauge("workers") == 7


def test_histogram_computes_count_sum_min_max_mean(registry):
    for value in (1.0, 2.0, 3.0, 4.0):
        registry.histogram("latency", value)
    stats = registry.get_histogram("latency")
    assert stats["count"] == 4
    assert stats["sum"] == pytest.approx(10.0)
    assert stats["min"] == pytest.approx(1.0)
    assert stats["max"] == pytest.approx(4.0)
    assert stats["mean"] == pytest.approx(2.5)


def test_histogram_single_value(registry):
    registry.histogram("size", 5.0)
    stats = registry.get_histogram("size")
    assert stats["count"] == 1
    assert stats["sum"] == pytest.approx(5.0)
    assert stats["min"] == pytest.approx(5.0)
    assert stats["max"] == pytest.approx(5.0)
    assert stats["mean"] == pytest.approx(5.0)


def test_histogram_unknown_returns_empty_stats(registry):
    stats = registry.get_histogram("missing")
    assert stats["count"] == 0
    assert stats["sum"] == pytest.approx(0.0)
    assert stats["min"] is None
    assert stats["max"] is None
    assert stats["mean"] is None


def test_snapshot_returns_all_metric_types(registry):
    registry.counter("calls", 3)
    registry.gauge("gpu_util", 0.8)
    registry.histogram("latency", 1.5)
    snapshot = registry.snapshot()
    assert snapshot["counters"] == {"calls": 3}
    assert snapshot["gauges"] == {"gpu_util": 0.8}
    assert snapshot["histograms"]["latency"]["count"] == 1


def test_reset_clears_everything(registry):
    registry.counter("calls", 3)
    registry.gauge("gpu_util", 0.8)
    registry.histogram("latency", 1.5)
    registry.reset()
    snapshot = registry.snapshot()
    assert snapshot == {"counters": {}, "gauges": {}, "histograms": {}}


def test_incr_decr_helpers(registry):
    registry.incr("alerts")
    registry.incr("alerts")
    registry.decr("alerts")
    assert registry.get_counter("alerts") == 1


def test_timed_decorator_sync_records_sample():
    @timed("sync_op")
    def work():
        time.sleep(0.01)
        return "done"

    assert work() == "done"
    stats = metrics_registry.get_histogram("sync_op")
    assert stats["count"] == 1
    assert stats["sum"] == pytest.approx(0.01, abs=0.05)
    assert stats["min"] == pytest.approx(0.01, abs=0.05)


def test_timed_decorator_async_records_sample():
    @timed("async_op")
    async def work():
        await asyncio.sleep(0.01)
        return "done"

    result = asyncio.run(work())
    assert result == "done"
    stats = metrics_registry.get_histogram("async_op")
    assert stats["count"] == 1
    assert stats["sum"] == pytest.approx(0.01, abs=0.05)


def test_thread_safety_counter_increments(registry):
    iterations = 1000
    threads = 8

    def worker():
        for _ in range(iterations):
            registry.counter("shared")

    thread_list = [threading.Thread(target=worker) for _ in range(threads)]
    for t in thread_list:
        t.start()
    for t in thread_list:
        t.join()

    assert registry.get_counter("shared") == iterations * threads
