"""Tests that stream metrics are measured from the events.

events_per_second was random.uniform(10, 1000), and any event without a
recorded latency contributed random.uniform(1, 100) to the latency average.
"""

import inspect
from datetime import datetime, timedelta, timezone

import pytest

from src.real_time_streaming import stream_analytics as stream_analytics_module
from src.real_time_streaming.models import StreamEvent
from src.real_time_streaming.stream_analytics import StreamAnalytics
from src.real_time_streaming.store import StreamStore


@pytest.fixture
def store():
    return StreamStore()


@pytest.fixture
def analytics(store):
    return StreamAnalytics(store=store)


def add_event(store, stream="s1", seconds_ago=0, latency=None):
    payload = {} if latency is None else {"latency_ms": latency}
    return store.add_event(stream, StreamEvent(
        event_type="txn",
        source="gateway",
        payload=payload,
        timestamp=datetime.now(timezone.utc) - timedelta(seconds=seconds_ago),
    ))


class TestDeterminism:
    """Stream metrics must be measured."""

    def test_module_does_not_import_random(self):
        source = inspect.getsource(stream_analytics_module)
        assert "import random" not in source

    def test_repeated_computation_agrees(self, store, analytics):
        for i in range(5):
            add_event(store, seconds_ago=5 - i, latency=10.0)

        first = analytics.compute_stream_metrics("s1")
        second = analytics.compute_stream_metrics("s1")

        assert first.events_per_second == second.events_per_second
        assert first.avg_latency_ms == second.avg_latency_ms


class TestThroughput:
    """Events per second comes from event timestamps."""

    def test_idle_stream_reports_zero(self, analytics):
        assert analytics.compute_stream_metrics("never_used").events_per_second == 0.0

    def test_single_event_reports_zero(self, store, analytics):
        add_event(store)

        assert analytics.compute_stream_metrics("s1").events_per_second == 0.0

    def test_rate_matches_the_timestamps(self, store, analytics):
        # 11 events spanning 10 seconds is 10 intervals -> 1.0 per second.
        for i in range(11):
            add_event(store, seconds_ago=10 - i)

        assert analytics.compute_stream_metrics("s1").events_per_second == pytest.approx(1.0)

    def test_a_busier_stream_rates_higher(self, store, analytics):
        for i in range(5):
            add_event(store, stream="slow", seconds_ago=20 - i * 4)
        for i in range(5):
            add_event(store, stream="fast", seconds_ago=4 - i)

        slow = analytics.compute_stream_metrics("slow").events_per_second
        fast = analytics.compute_stream_metrics("fast").events_per_second

        assert fast > slow

    def test_simultaneous_events_do_not_divide_by_zero(self, store, analytics):
        moment = datetime.now(timezone.utc)
        for _ in range(3):
            store.add_event("s1", StreamEvent(
                event_type="txn", source="gateway", timestamp=moment,
            ))

        assert analytics.compute_stream_metrics("s1").events_per_second == 0.0


class TestLatency:
    """Only recorded latencies contribute."""

    def test_recorded_latencies_are_averaged(self, store, analytics):
        add_event(store, seconds_ago=2, latency=10.0)
        add_event(store, seconds_ago=1, latency=30.0)

        assert analytics.compute_stream_metrics("s1").avg_latency_ms == pytest.approx(20.0)

    def test_events_without_latency_are_not_invented(self, store, analytics):
        # The old default of random.uniform(1, 100) meant a stream recording
        # no latency at all still reported roughly 50ms.
        add_event(store, seconds_ago=2)
        add_event(store, seconds_ago=1)

        assert analytics.compute_stream_metrics("s1").avg_latency_ms == 0.0

    def test_unrecorded_events_do_not_dilute_real_ones(self, store, analytics):
        add_event(store, seconds_ago=3, latency=10.0)
        add_event(store, seconds_ago=2)
        add_event(store, seconds_ago=1)

        assert analytics.compute_stream_metrics("s1").avg_latency_ms == pytest.approx(10.0)

    def test_non_numeric_latency_is_ignored(self, store, analytics):
        add_event(store, seconds_ago=2, latency="fast")
        add_event(store, seconds_ago=1, latency=20.0)

        assert analytics.compute_stream_metrics("s1").avg_latency_ms == pytest.approx(20.0)

    def test_boolean_latency_is_not_treated_as_a_number(self, store, analytics):
        add_event(store, seconds_ago=2, latency=True)
        add_event(store, seconds_ago=1, latency=20.0)

        assert analytics.compute_stream_metrics("s1").avg_latency_ms == pytest.approx(20.0)


class TestOtherMetrics:
    """The rest of the metrics still work."""

    def test_queue_depth_counts_events(self, store, analytics):
        for i in range(4):
            add_event(store, seconds_ago=4 - i)

        assert analytics.compute_stream_metrics("s1").queue_depth == 4

    def test_streams_are_independent(self, store, analytics):
        add_event(store, stream="a", latency=5.0)
        add_event(store, stream="b", latency=99.0)

        assert analytics.compute_stream_metrics("a").avg_latency_ms == pytest.approx(5.0)
