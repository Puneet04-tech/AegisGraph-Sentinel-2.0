import threading
import time
from unittest import mock

from utils.rate_limiter import RateLimiter


def test_rate_limiter_initial_capacity():
    """Verify rate limiter allows initial capacity to be consumed."""
    limiter = RateLimiter(capacity=5, refill_rate=1)
    for _ in range(5):
        assert limiter.consume() is True
    assert limiter.consume() is False


def test_rate_limiter_refill():
    """Verify rate limiter refills tokens over time."""
    limiter = RateLimiter(capacity=2, refill_rate=10)
    # Consume all initial tokens
    assert limiter.consume() is True
    assert limiter.consume() is True
    assert limiter.consume() is False

    # Sleep for 0.15s -> should refill 1.5 tokens -> capacity is 2
    time.sleep(0.15)
    assert limiter.consume() is True
    # Sleep again to refill
    time.sleep(0.15)
    assert limiter.consume() is True


def test_rate_limiter_ignores_wall_clock_changes():
    """A wall clock adjustment must not affect refill.

    time.time can step backwards on an NTP correction. Measuring refill against
    it left the bucket unable to recover until the wall clock passed its former
    value, locking the caller out for the size of the correction.
    """
    limiter = RateLimiter(capacity=2, refill_rate=100)
    assert limiter.consume() is True
    assert limiter.consume() is True
    assert limiter.consume() is False

    with mock.patch("time.time", return_value=time.time() - 3600):
        time.sleep(0.05)
        assert limiter.consume() is True, (
            "the bucket did not refill while the wall clock was set back, so "
            "refill is still measured against a non-monotonic clock"
        )


def test_rate_limiter_uses_a_monotonic_reference():
    """The stored reference point must come from the monotonic clock."""
    before = time.monotonic()
    limiter = RateLimiter(capacity=1, refill_rate=1)
    after = time.monotonic()

    assert before <= limiter.last_refill <= after


def test_rate_limiter_concurrency():
    """Verify rate limiter is thread-safe and does not over-allocate."""
    limiter = RateLimiter(capacity=100, refill_rate=1)
    results = []

    def worker():
        for _ in range(10):
            results.append(limiter.consume())

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Total requests made: 10 * 10 = 100. All should succeed.
    assert len(results) == 100
    assert all(results)

    # Next one should fail
    assert limiter.consume() is False
