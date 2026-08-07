"""Unit tests for throttling and backpressure utilities."""

import time

import pytest

from src.utils.throttle import RateGate, TokenBucket, throttle_iterable


class FakeClock:
    def __init__(self, start=0.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class TestTokenBucketInit:
    def test_init_accepts_capacity_and_rate(self):
        bucket = TokenBucket(capacity=5, refill_rate=2.0, clock=FakeClock())
        assert bucket.peek() == 5.0

    def test_init_rejects_non_positive_capacity(self):
        with pytest.raises(ValueError):
            TokenBucket(capacity=0, refill_rate=1.0)
        with pytest.raises(ValueError):
            TokenBucket(capacity=-1, refill_rate=1.0)

    def test_init_rejects_negative_refill_rate(self):
        with pytest.raises(ValueError):
            TokenBucket(capacity=5, refill_rate=-0.5)

    def test_init_accepts_zero_refill_rate(self):
        bucket = TokenBucket(capacity=5, refill_rate=0.0, clock=FakeClock())
        assert bucket.consume(5) is True
        assert bucket.consume() is False


class TestTokenBucketConsume:
    def test_allows_up_to_capacity_immediately(self):
        bucket = TokenBucket(capacity=3, refill_rate=1.0, clock=FakeClock())
        assert bucket.consume() is True
        assert bucket.consume() is True
        assert bucket.consume() is True
        assert bucket.consume() is False

    def test_denies_beyond_capacity_without_refill(self):
        bucket = TokenBucket(capacity=1, refill_rate=1.0, clock=FakeClock())
        assert bucket.consume() is True
        assert bucket.consume() is False

    def test_consume_fractional_tokens(self):
        bucket = TokenBucket(capacity=1.0, refill_rate=1.0, clock=FakeClock())
        assert bucket.consume(0.4) is True
        assert bucket.consume(0.4) is True
        assert bucket.consume(0.4) is False

    def test_consume_does_not_partially_deduct_on_failure(self):
        bucket = TokenBucket(capacity=1.0, refill_rate=0.0, clock=FakeClock())
        assert bucket.consume(2.0) is False
        assert bucket.peek() == 1.0

    def test_consume_rejects_non_positive_tokens(self):
        bucket = TokenBucket(capacity=5, refill_rate=1.0, clock=FakeClock())
        with pytest.raises(ValueError):
            bucket.consume(0)
        with pytest.raises(ValueError):
            bucket.consume(-1)


class TestTokenBucketRefill:
    def test_tokens_accrue_over_time(self):
        clock = FakeClock()
        bucket = TokenBucket(capacity=10, refill_rate=2.0, clock=clock)
        bucket.consume(6)
        assert bucket.peek() == 4.0
        clock.advance(2.0)
        assert bucket.peek() == 8.0
        clock.advance(1.0)
        assert bucket.peek() == 10.0

    def test_accrual_is_capped_at_capacity(self):
        clock = FakeClock()
        bucket = TokenBucket(capacity=10, refill_rate=1.0, clock=clock)
        clock.advance(100.0)
        assert bucket.peek() == 10.0

    def test_peek_is_not_destructive(self):
        clock = FakeClock()
        bucket = TokenBucket(capacity=10, refill_rate=1.0, clock=clock)
        bucket.consume(8)
        clock.advance(1.0)
        first = bucket.peek()
        assert bucket.peek() == first

    def test_manual_refill_adds_tokens(self):
        bucket = TokenBucket(capacity=5, refill_rate=0.0, clock=FakeClock())
        bucket.consume(3)
        bucket.refill(2)
        assert bucket.peek() == 4.0

    def test_manual_refill_capped_at_capacity(self):
        bucket = TokenBucket(capacity=5, refill_rate=0.0, clock=FakeClock())
        bucket.consume(4)
        bucket.refill(10)
        assert bucket.peek() == 5.0
        assert bucket.consume(5) is True

    def test_refill_rejects_negative_amount(self):
        bucket = TokenBucket(capacity=5, refill_rate=1.0, clock=FakeClock())
        with pytest.raises(ValueError):
            bucket.refill(-1)


class TestRateGate:
    def test_first_call_returns_immediately(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr(time, "sleep", sleeps.append)
        gate = RateGate(interval_seconds=1.0)
        gate.wait_if_needed()
        assert sleeps == []

    def test_second_call_within_interval_waits(self, monkeypatch):
        clock = FakeClock()
        monkeypatch.setattr(time, "monotonic", clock)
        sleeps = []
        monkeypatch.setattr(time, "sleep", sleeps.append)
        gate = RateGate(interval_seconds=1.0)
        gate.wait_if_needed()
        clock.advance(0.4)
        gate.wait_if_needed()
        assert sleeps == [0.6]

    def test_call_after_interval_does_not_wait(self, monkeypatch):
        clock = FakeClock()
        monkeypatch.setattr(time, "monotonic", clock)
        sleeps = []
        monkeypatch.setattr(time, "sleep", sleeps.append)
        gate = RateGate(interval_seconds=1.0)
        gate.wait_if_needed()
        clock.advance(1.0)
        gate.wait_if_needed()
        assert sleeps == []

    def test_wait_tracks_latest_release(self, monkeypatch):
        clock = FakeClock()
        monkeypatch.setattr(time, "monotonic", clock)
        sleeps = []
        monkeypatch.setattr(time, "sleep", sleeps.append)
        gate = RateGate(interval_seconds=1.0)
        gate.wait_if_needed()
        clock.advance(0.5)
        gate.wait_if_needed()
        clock.advance(0.5)
        gate.wait_if_needed()
        assert len(sleeps) == 2

    def test_init_rejects_non_positive_interval(self):
        with pytest.raises(ValueError):
            RateGate(interval_seconds=0)
        with pytest.raises(ValueError):
            RateGate(interval_seconds=-1)


class TestThrottleIterable:
    def test_yields_all_items(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr(time, "sleep", sleeps.append)
        clock = FakeClock()
        result = list(throttle_iterable(["a", "b", "c"], 0.5, clock=clock))
        assert result == ["a", "b", "c"]
        assert len(sleeps) == 2

    def test_first_item_immediate_then_sleeps_between(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr(time, "sleep", sleeps.append)
        clock = FakeClock()
        result = list(throttle_iterable(range(4), 2.0, clock=clock))
        assert result == [0, 1, 2, 3]
        assert len(sleeps) == 3
        assert all(sleep == 2.0 for sleep in sleeps)

    def test_empty_iterable_yields_nothing(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr(time, "sleep", sleeps.append)
        clock = FakeClock()
        result = list(throttle_iterable([], 1.0, clock=clock))
        assert result == []
        assert sleeps == []

    def test_without_clock_uses_monotonic(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr(time, "sleep", sleeps.append)
        result = list(throttle_iterable([1, 2, 3], 0.0))
        assert result == [1, 2, 3]
        assert sleeps == []

    def test_single_item_yields_without_sleep(self, monkeypatch):
        sleeps = []
        monkeypatch.setattr(time, "sleep", sleeps.append)
        clock = FakeClock()
        result = list(throttle_iterable([42], 5.0, clock=clock))
        assert result == [42]
        assert sleeps == []
