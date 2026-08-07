"""Timing and execution-tracking helpers for performance instrumentation."""

import asyncio
import functools
import math
import time

from typing import Any, Callable, Optional


def elapsed(start_ns: int) -> float:
    """Return seconds elapsed since a time.perf_counter_ns() start."""
    return max(0.0, (time.perf_counter_ns() - start_ns) / 1e9)


class Stopwatch:
    """Measure elapsed wall-clock time with context manager or manual control."""

    def __init__(self) -> None:
        self.elapsed_seconds: float = 0.0
        self._start_ns: Optional[int] = None

    def __enter__(self) -> "Stopwatch":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.stop()
        return False

    def start(self) -> None:
        self._start_ns = time.perf_counter_ns()

    def stop(self) -> float:
        if self._start_ns is None:
            self.elapsed_seconds = 0.0
        else:
            self.elapsed_seconds = elapsed(self._start_ns)
            self._start_ns = None
        return self.elapsed_seconds

    def reset(self) -> None:
        self.elapsed_seconds = 0.0
        self._start_ns = None


def measure(label: str, sink: Optional[Callable[[str, float], None]] = None):
    """Record execution time of the decorated function into an optional sink."""

    def decorator(fn):
        if asyncio.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                start = time.perf_counter_ns()
                try:
                    return await fn(*args, **kwargs)
                finally:
                    seconds = elapsed(start)
                    if sink is not None:
                        sink(label, seconds)

            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            start = time.perf_counter_ns()
            try:
                return fn(*args, **kwargs)
            finally:
                seconds = elapsed(start)
                if sink is not None:
                    sink(label, seconds)

        return wrapper

    return decorator


def rate_tracker():
    """Return a track(value) closure whose .stats() reports rolling counters."""

    _data: list = []

    def track(value: float) -> None:
        _data.append((value, time.perf_counter()))

    def stats() -> dict:
        if not _data:
            return {"count": 0, "sum": 0.0, "mean": 0.0, "window_seconds": 0.0}
        count = len(_data)
        total = sum(v for v, _ in _data)
        window = max(0.0, _data[-1][1] - _data[0][1])
        return {
            "count": count,
            "sum": total,
            "mean": total / count,
            "window_seconds": window,
        }

    track.stats = stats
    return track


def quantile_sorted(values, q: float) -> Optional[float]:
    """Nearest-rank quantile over a sorted copy; empty input returns None."""
    if not values:
        return None
    ordered = sorted(values)
    n = len(ordered)
    q = min(1.0, max(0.0, q))
    index = max(0, min(n - 1, math.ceil(q * n) - 1))
    return ordered[index]
