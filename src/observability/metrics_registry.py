"""In-process metrics registry with thread-safe counters, gauges and histograms."""

import asyncio
import functools
import threading
import time

from collections import defaultdict


class MetricsRegistry:
    """Thread-safe in-process store for counters, gauges and histograms."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._counters = defaultdict(int)
        self._gauges = {}
        self._histograms = {}

    def counter(self, name: str, delta: int = 1) -> None:
        with self._lock:
            self._counters[name] += delta

    def get_counter(self, name: str) -> int:
        with self._lock:
            return self._counters.get(name, 0)

    def incr(self, name: str) -> None:
        self.counter(name, 1)

    def decr(self, name: str) -> None:
        self.counter(name, -1)

    def gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def get_gauge(self, name: str) -> float:
        with self._lock:
            return self._gauges.get(name, 0)

    def histogram(self, name: str, value: float) -> None:
        with self._lock:
            stats = self._histograms.get(name)
            if stats is None:
                stats = {"count": 0, "sum": 0.0, "min": value, "max": value}
                self._histograms[name] = stats
            stats["count"] += 1
            stats["sum"] += value
            if value < stats["min"]:
                stats["min"] = value
            if value > stats["max"]:
                stats["max"] = value

    def get_histogram(self, name: str) -> dict:
        with self._lock:
            stats = self._histograms.get(name)
            if stats is None:
                return {"count": 0, "sum": 0.0, "min": None, "max": None, "mean": None}
            return {
                "count": stats["count"],
                "sum": stats["sum"],
                "min": stats["min"],
                "max": stats["max"],
                "mean": stats["sum"] / stats["count"],
            }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": {
                    name: self.get_histogram(name) for name in sorted(self._histograms)
                },
            }

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()


metrics_registry = MetricsRegistry()


def timed(name: str):
    """Decorator recording wall-clock seconds of a call into the histogram ``name``."""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                metrics_registry.histogram(name, time.perf_counter() - start)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                return await func(*args, **kwargs)
            finally:
                metrics_registry.histogram(name, time.perf_counter() - start)

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator
