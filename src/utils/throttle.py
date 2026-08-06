"""Throttling primitives: token bucket, minimum-interval gate, paced iteration."""

import time


class TokenBucket:
    """Classic token bucket rate limiter.

    Tokens accrue continuously at ``refill_rate`` tokens per second up to
    ``capacity``. The clock is injectable for deterministic tests and
    defaults to ``time.monotonic``.
    """

    def __init__(self, capacity, refill_rate, *, clock=None):
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if refill_rate < 0:
            raise ValueError("refill_rate must be non-negative")
        self._capacity = float(capacity)
        self._refill_rate = float(refill_rate)
        self._clock = clock if clock is not None else time.monotonic
        self._tokens = float(capacity)
        self._last = self._clock()

    def _accrue(self):
        now = self._clock()
        if self._refill_rate:
            elapsed = max(0.0, now - self._last)
            self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_rate)
        self._last = now

    def consume(self, tokens=1.0):
        if tokens <= 0:
            raise ValueError("tokens must be positive")
        self._accrue()
        if self._tokens < tokens:
            return False
        self._tokens -= tokens
        return True

    def peek(self):
        self._accrue()
        return self._tokens

    def refill(self, amount):
        if amount < 0:
            raise ValueError("amount must be non-negative")
        self._accrue()
        self._tokens = min(self._capacity, self._tokens + amount)


class RateGate:
    """Enforce a minimum interval between releases, blocking as needed."""

    def __init__(self, interval_seconds):
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self._interval = float(interval_seconds)
        self._last_release = None

    def wait_if_needed(self):
        now = time.monotonic()
        if self._last_release is not None:
            elapsed = now - self._last_release
            if elapsed < self._interval:
                time.sleep(self._interval - elapsed)
        self._last_release = time.monotonic()


def throttle_iterable(items, interval_seconds, *, clock=None):
    """Yield ``items`` with a minimum gap between consecutive yields.

    The first item is yielded immediately. Sleeping uses ``time.sleep`` so
    tests may monkeypatch it; ``clock`` (default ``time.monotonic``) only
    measures elapsed time and does not advance during a sleep.
    """
    if interval_seconds < 0:
        raise ValueError("interval_seconds must be non-negative")
    now = clock if clock is not None else time.monotonic
    last = None
    for item in items:
        if last is not None:
            elapsed = now() - last
            if elapsed < interval_seconds:
                time.sleep(interval_seconds - elapsed)
        last = now()
        yield item
