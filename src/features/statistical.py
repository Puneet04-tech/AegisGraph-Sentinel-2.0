"""Statistical feature extraction for transaction and behavior sequences.

Pure-statistics helpers used across fraud-detection feature pipelines:
descriptive summaries, z-scores, percentiles, rolling means, coefficient of
variation, Shannon entropy and threshold counting.

All helpers are NaN-free by construction and degrade gracefully on empty or
degenerate inputs so downstream model features never blow up.
"""

import math
import statistics


def describe_sequence(values: list[float]) -> dict[str, float]:
    """Return summary statistics for a sequence of values.

    Population standard deviation is used; a single-element sequence has a
    standard deviation of 0.0 and an empty sequence yields all zeros.
    """
    if not values:
        return {
            "mean": 0.0,
            "median": 0.0,
            "std": 0.0,
            "min": 0.0,
            "max": 0.0,
            "sum": 0.0,
            "count": 0.0,
            "range": 0.0,
        }
    return {
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "std": statistics.pstdev(values),
        "min": float(min(values)),
        "max": float(max(values)),
        "sum": float(sum(values)),
        "count": float(len(values)),
        "range": float(max(values) - min(values)),
    }


def zscore(value: float, mean: float, std: float) -> float:
    """Standard score of ``value`` given a population mean and std.

    Returns 0.0 when the standard deviation is zero so constant features do
    not produce infinities.
    """
    if std == 0.0:
        return 0.0
    return (value - mean) / std


def percentile(values: list[float], p: float) -> float:
    """Interpolated percentile of ``values`` at rank ``p`` in [0, 100].

    ``p`` is clamped to [0, 100]; 0 returns the minimum, 100 the maximum, and
    intermediate ranks are linearly interpolated between adjacent sorted
    values (same convention as numpy's default).
    """
    if not values:
        raise ValueError("cannot compute percentile of an empty sequence")
    p = max(0.0, min(100.0, float(p)))
    ordered = sorted(values)
    if p == 0.0:
        return float(ordered[0])
    if p == 100.0:
        return float(ordered[-1])
    rank = p / 100.0 * (len(ordered) - 1)
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return float(ordered[lower])
    weight = rank - lower
    return float(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)


def rolling_mean(values: list[float], window: int) -> list[float]:
    """Rolling-window mean with prefix handling for the leading positions.

    Output has the same length as ``values``.  For the first ``window - 1``
    positions the mean is computed over the available prefix so no NaN is ever
    emitted, even when ``window`` exceeds the sequence length.
    """
    if window < 1:
        raise ValueError("window must be >= 1")
    result = []
    for i in range(len(values)):
        segment = values[max(0, i - window + 1) : i + 1]
        result.append(sum(segment) / len(segment))
    return result


def coefficient_of_variation(values: list[float]) -> float:
    """Population coefficient of variation (std / mean).

    Returns 0.0 for empty sequences or sequences whose mean is zero.
    """
    if not values:
        return 0.0
    mean = statistics.fmean(values)
    if mean == 0.0:
        return 0.0
    return statistics.pstdev(values) / mean


def entropy(counts: list[float]) -> float:
    """Shannon entropy in bits (base 2) of a categorical distribution.

    Accepts either raw counts or proportions; values are normalized internally
    so both forms produce identical results.  Zero (and negative) counts are
    ignored, and an empty or all-zero input yields 0.0 bits.
    """
    positive = [count for count in counts if count > 0]
    total = sum(positive)
    if total <= 0.0:
        return 0.0
    return float(-sum((count / total) * math.log2(count / total) for count in positive))


def count_above_threshold(values: list[float], threshold: float) -> int:
    """Count how many values are strictly greater than ``threshold``."""
    return sum(1 for value in values if value > threshold)
