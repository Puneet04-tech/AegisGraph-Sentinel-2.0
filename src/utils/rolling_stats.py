"""Streaming rolling statistics over a sliding time window."""

import math
import time
from typing import Callable, List, Optional, Tuple


class RollingStats:
    """Tracks recent values with a sliding time window.

    Values are kept in insertion order and pruned once they are older than
    ``window_seconds``. Each value may carry its own monotonic timestamp;
    when omitted the internal clock (``time.monotonic`` by default) is used.

    Empty-window semantics: ``mean``/``min``/``max``/``p95`` return None,
    ``count``/``sum`` return 0.0/0, and ``variance``/``std``/``rate`` return
    0.0. This keeps aggregate consumers safe without sentinel handling.
    """

    def __init__(
        self,
        window_seconds: float,
        *,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._window_seconds = float(window_seconds)
        self._clock = clock or time.monotonic
        self._values: List[Tuple[float, float]] = []

    def _now(self) -> float:
        return self._clock()

    def _prune(self, now: float) -> None:
        cutoff = now - self._window_seconds
        while self._values and self._values[0][0] <= cutoff:
            self._values.pop(0)

    def add(self, value: float, timestamp: Optional[float] = None) -> None:
        ts = timestamp if timestamp is not None else self._now()
        self._prune(ts)
        self._values.append((ts, value))

    def _raw(self) -> List[float]:
        self._prune(self._now())
        return [v for _, v in self._values]

    def reset(self) -> None:
        self._values.clear()

    def count(self) -> int:
        return len(self._raw())

    def sum(self) -> float:
        return sum(self._raw())

    def mean(self) -> Optional[float]:
        values = self._raw()
        if not values:
            return None
        return sum(values) / len(values)

    def min(self) -> Optional[float]:
        values = self._raw()
        return min(values) if values else None

    def max(self) -> Optional[float]:
        values = self._raw()
        return max(values) if values else None

    def variance(self) -> float:
        values = self._raw()
        if not values:
            return 0.0
        mean = sum(values) / len(values)
        return sum((v - mean) ** 2 for v in values) / len(values)

    def std(self) -> float:
        return self.variance() ** 0.5

    def p95(self) -> Optional[float]:
        values = sorted(self._raw())
        if not values:
            return None
        index = math.ceil(0.95 * len(values)) - 1
        return values[index]

    def rate(self) -> float:
        self._prune(self._clock())
        if not self._values:
            return 0.0
        elapsed = self._clock() - self._values[0][0]
        if elapsed <= 0:
            return 0.0
        return len(self._values) / elapsed
