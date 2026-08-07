"""Helpers for bucketing, smoothing, and gap-filling time series data."""

from typing import Dict, List, Optional, Sequence, Tuple


def moving_average(
    values: Sequence[float], window: int
) -> List[Optional[float]]:
    """Return rolling averages with None padding for the first window-1 slots.

    ``window <= 0`` raises ValueError. When ``window > len(values)`` every
    slot is None because no full window exists. A window of 1 is the identity.
    """
    if window <= 0:
        raise ValueError("window must be positive")
    n = len(values)
    if window > n:
        return [None] * n
    if window == 1:
        return list(values)
    out: List[Optional[float]] = [None] * (window - 1)
    running = sum(values[: window - 1])
    for i in range(window - 1, n):
        running += values[i]
        out.append(running / window)
        running -= values[i - window + 1]
    return out


def time_bucket(timestamp: float, bucket_seconds: float) -> int:
    """Return the bucket start containing ``timestamp`` via floor division."""
    if bucket_seconds <= 0:
        raise ValueError("bucket_seconds must be positive")
    return int(timestamp // bucket_seconds) * int(bucket_seconds)


def resample_series(
    points: Sequence[Tuple[float, float]], bucket_seconds: float
) -> Dict[int, float]:
    """Bucket ``(timestamp, value)`` points and sum values per bucket.

    Points do not need to be pre-sorted; bucket membership is order
    independent. Keys are ``floor(ts / bucket_seconds) * bucket_seconds``.
    """
    if bucket_seconds <= 0:
        raise ValueError("bucket_seconds must be positive")
    buckets: Dict[int, float] = {}
    for ts, value in points:
        start = int(ts // bucket_seconds) * int(bucket_seconds)
        buckets[start] = buckets.get(start, 0.0) + value
    return buckets


def fill_gaps(
    series: Dict[int, float],
    start: int,
    end: int,
    step: int,
    fill: float = 0.0,
) -> Dict[int, float]:
    """Return a dense series from ``start`` to ``end`` stepping by ``step``.

    Missing timestamps are filled with ``fill``; present values are kept.
    A ``start`` beyond ``end`` yields an empty dict.
    """
    if step <= 0:
        raise ValueError("step must be positive")
    if start > end:
        return {}
    result: Dict[int, float] = {}
    ts = start
    while ts <= end:
        result[ts] = series.get(ts, fill)
        ts += step
    return result


def first_and_last(
    points: Sequence[Tuple[float, float]],
) -> Tuple[Optional[float], Optional[float]]:
    """Return (first_ts, last_ts) of points sorted by timestamp.

    Empty input returns (None, None). The input itself is not mutated.
    """
    if not points:
        return (None, None)
    ordered = sorted(points, key=lambda p: p[0])
    return ordered[0][0], ordered[-1][0]
