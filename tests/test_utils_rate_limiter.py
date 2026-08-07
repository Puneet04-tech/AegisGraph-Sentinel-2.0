"""Unit tests for the sliding-window rate limiter."""

import threading
import time

import pytest

from src.utils.rate_limiter import SlidingWindowRateLimiter


class TestSlidingWindowRateLimiterInit:
    def test_init_sets_limit_and_window(self):
        limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=5.0)
        assert limiter.get_limit() == 10
        assert limiter.get_window_size() == 5.0

    def test_init_rejects_non_positive_limit(self):
        with pytest.raises(ValueError):
            SlidingWindowRateLimiter(max_requests=0, window_seconds=5.0)

    def test_init_rejects_non_positive_window(self):
        with pytest.raises(ValueError):
            SlidingWindowRateLimiter(max_requests=10, window_seconds=0)

    def test_init_accepts_custom_clock(self):
        calls = []

        def fake_clock():
            calls.append(1)
            return 100.0

        limiter = SlidingWindowRateLimiter(5, 1.0, clock=fake_clock)
        limiter.allow()
        assert calls


class TestSlidingWindowRateLimiterAllow:
    def test_allow_consumes_tokens_up_to_limit(self):
        limiter = SlidingWindowRateLimiter(3, 10.0)
        assert limiter.allow() is True
        assert limiter.allow() is True
        assert limiter.allow() is True
        assert limiter.allow() is False

    def test_allow_is_isolated_per_key(self):
        limiter = SlidingWindowRateLimiter(1, 10.0)
        assert limiter.allow("user-a") is True
        assert limiter.allow("user-a") is False
        assert limiter.allow("user-b") is True

    def test_allow_defaults_to_default_key(self):
        limiter = SlidingWindowRateLimiter(1, 10.0)
        assert limiter.allow() is True
        assert limiter.allow() is False


class TestSlidingWindowRateLimiterWindowExpiry:
    def test_window_expires_and_allows_again(self):
        t0 = [100.0]
        limiter = SlidingWindowRateLimiter(1, 5.0, clock=lambda: t0[0])
        assert limiter.allow() is True
        assert limiter.allow() is False
        t0[0] = 105.1
        assert limiter.allow() is True

    def test_sliding_window_prunes_old_entries(self):
        t0 = [0.0]
        limiter = SlidingWindowRateLimiter(3, 10.0, clock=lambda: t0[0])
        for _ in range(3):
            assert limiter.allow() is True
        t0[0] = 5.0
        assert limiter.allow() is False
        t0[0] = 15.0
        assert limiter.allow() is True


class TestSlidingWindowRateLimiterRemaining:
    def test_remaining_decreases_as_requests_are_recorded(self):
        limiter = SlidingWindowRateLimiter(4, 10.0)
        assert limiter.remaining() == 4
        limiter.allow()
        assert limiter.remaining() == 3
        limiter.allow()
        assert limiter.remaining() == 2

    def test_remaining_never_below_zero(self):
        limiter = SlidingWindowRateLimiter(2, 10.0)
        for _ in range(4):
            limiter.allow()
        assert limiter.remaining() == 0

    def test_remaining_restored_after_window_elapses(self):
        t0 = [0.0]
        limiter = SlidingWindowRateLimiter(2, 5.0, clock=lambda: t0[0])
        limiter.allow()
        limiter.allow()
        assert limiter.remaining() == 0
        t0[0] = 6.0
        assert limiter.remaining() == 2


class TestSlidingWindowRateLimiterReset:
    def test_reset_clears_recorded_requests(self):
        limiter = SlidingWindowRateLimiter(1, 10.0)
        assert limiter.allow() is True
        assert limiter.allow() is False
        limiter.reset()
        assert limiter.allow() is True

    def test_reset_targets_single_key(self):
        limiter = SlidingWindowRateLimiter(1, 10.0)
        limiter.allow("a")
        limiter.allow("b")
        limiter.reset("a")
        assert limiter.allow("a") is True
        assert limiter.allow("b") is False


class TestSlidingWindowRateLimiterThreadSafety:
    def test_concurrent_allows_respect_limit(self):
        limiter = SlidingWindowRateLimiter(50, 60.0)
        results = []
        lock = threading.Lock()

        def worker():
            allowed = sum(1 for _ in range(20) if limiter.allow("shared"))
            with lock:
                results.append(allowed)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(results) == 50


class TestSlidingWindowRateLimiterRealClock:
    def test_real_clock_window_elapses(self):
        limiter = SlidingWindowRateLimiter(1, 0.05)
        assert limiter.allow() is True
        assert limiter.allow() is False
        time.sleep(0.1)
        assert limiter.allow() is True
