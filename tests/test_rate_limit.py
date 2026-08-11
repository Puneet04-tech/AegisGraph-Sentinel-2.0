import threading
import time
import pytest
from utils.rate_limit import TokenBucketRateLimiter, RateLimiter


def test_token_bucket_capacity_and_exhaustion():
    limiter = TokenBucketRateLimiter(capacity=5.0, window_seconds=60.0)
    client_key = "192.168.1.100"

    # Consume 5 allowed tokens
    for _ in range(5):
        assert limiter.consume(client_key) is True

    # 6th request should be blocked
    assert limiter.consume(client_key) is False


def test_per_client_isolation():
    limiter = TokenBucketRateLimiter(capacity=2.0, window_seconds=60.0)

    # Exhaust Client A
    assert limiter.consume("client_a") is True
    assert limiter.consume("client_a") is True
    assert limiter.consume("client_a") is False

    # Client B should still have full capacity
    assert limiter.consume("client_b") is True
    assert limiter.consume("client_b") is True


def test_token_bucket_refill():
    limiter = TokenBucketRateLimiter(capacity=2.0, window_seconds=1.0)
    client_key = "refill_client"

    assert limiter.consume(client_key) is True
    assert limiter.consume(client_key) is True
    assert limiter.consume(client_key) is False

    # Sleep to allow refill
    time.sleep(1.1)
    assert limiter.consume(client_key) is True


def test_concurrent_consumption_safety():
    limiter = TokenBucketRateLimiter(capacity=100.0, window_seconds=60.0)
    client_key = "concurrent_client"
    successful_consumptions = []
    lock = threading.Lock()

    def worker():
        if limiter.consume(client_key):
            with lock:
                successful_consumptions.append(1)

    threads = [threading.Thread(target=worker) for _ in range(120)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly 100 requests should succeed
    assert len(successful_consumptions) == 100
