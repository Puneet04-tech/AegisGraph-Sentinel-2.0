import threading
import time

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
