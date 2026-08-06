"""Pure, deterministic time-window utilities for velocity and transaction windows."""

import math
from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Iterable
from typing import Any


def _validate_window(window_seconds: float) -> None:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")


def bucket_start(ts: float, window_seconds: float) -> float:
    """Floor a timestamp to the nearest window boundary (at or before ts)."""
    _validate_window(window_seconds)
    return math.floor(ts / window_seconds) * window_seconds


def bucket_index(ts: float, window_seconds: float, epoch: float = 0.0) -> int:
    """Return the integer bucket index for ts relative to the epoch."""
    _validate_window(window_seconds)
    return math.floor((ts - epoch) / window_seconds)


def iter_windows(
    start_ts: float, end_ts: float, window_seconds: float
) -> Iterable[tuple[float, float]]:
    """Yield contiguous (bucket_start, bucket_end) pairs covering [start, end).

    Yields nothing for a zero-length range (start_ts == end_ts).
    """
    _validate_window(window_seconds)
    if end_ts < start_ts:
        raise ValueError("end_ts must be greater than or equal to start_ts")
    if end_ts == start_ts:
        return
    current = bucket_start(start_ts, window_seconds)
    while current < end_ts:
        yield current, current + window_seconds
        current += window_seconds


def group_by_window(
    items: Iterable[Any],
    window_seconds: float,
    *,
    ts_key: str = "timestamp",
) -> dict[int, list[Any]]:
    """Group dict items by bucket index, preserving order within each bucket."""
    _validate_window(window_seconds)
    groups: dict[int, list[Any]] = defaultdict(list)
    for item in items:
        if not isinstance(item, dict) or ts_key not in item:
            raise KeyError(f"item missing required key {ts_key!r}: {item!r}")
        groups[bucket_index(item[ts_key], window_seconds)].append(item)
    return dict(groups)


def rolling_window_count(timestamps: list[float], window_seconds: float) -> list[int]:
    """Count, per timestamp, all list entries within [ts - window, ts] inclusive."""
    _validate_window(window_seconds)
    ordered = sorted(timestamps)
    counts = []
    for ts in timestamps:
        low = bisect_left(ordered, ts - window_seconds)
        high = bisect_right(ordered, ts)
        counts.append(high - low)
    return counts
