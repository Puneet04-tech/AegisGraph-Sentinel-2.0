"""Sliding-window rate limiter with per-key isolation."""

import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict


class SlidingWindowRateLimiter:
    """Rate limits requests per key over a sliding time window.

    Tracks a deque of request timestamps per key and prunes entries older
    than ``window_seconds`` on each check. Thread-safe via a single lock.
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: float,
        *,
        clock=None,
    ) -> None:
        if max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._max_requests = max_requests
        self._window_seconds = float(window_seconds)
        self._clock = clock or time.time
        self._windows: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _now(self) -> float:
        return self._clock()

    def _prune(self, key: str, now: float) -> Deque[float]:
        window = self._windows[key]
        cutoff = now - self._window_seconds
        while window and window[0] <= cutoff:
            window.popleft()
        return window

    def allow(self, key: str = "default") -> bool:
        """Record one request if under the limit and return True."""
        now = self._now()
        with self._lock:
            window = self._prune(key, now)
            if len(window) >= self._max_requests:
                return False
            window.append(now)
            return True

    def remaining(self, key: str = "default") -> int:
        """Return how many requests are still allowed in the window."""
        now = self._now()
        with self._lock:
            window = self._prune(key, now)
            return self._max_requests - len(window)

    def reset(self, key: str = "default") -> None:
        """Clear all recorded requests for the key."""
        with self._lock:
            self._windows.pop(key, None)

    def get_window_size(self) -> float:
        return self._window_seconds

    def get_limit(self) -> int:
        return self._max_requests
