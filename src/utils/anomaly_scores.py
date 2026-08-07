"""Statistical anomaly scoring helpers for fraud signal detection.

Scores are distance measures: the absolute z-score for the ``zscore``
method and the distance beyond the IQR bound for the ``iqr`` method.
Empty and degenerate inputs return safe defaults so callers never need
sentinel handling.
"""

import statistics
from typing import List, Optional, Tuple

DEFAULT_Z_THRESHOLD = 3.0


def zscore_outlier(value: float, mean: float, std: float, *, z_threshold: float = DEFAULT_Z_THRESHOLD) -> bool:
    if value is None or mean is None or std is None:
        return False
    if std == 0:
        return False
    return abs(value - mean) / std > z_threshold


def _quartiles(values: List[float]) -> Tuple[Optional[float], Optional[float]]:
    sorted_values = sorted(values)
    n = len(sorted_values)
    if n < 4:
        return None, None

    def median(seq: List[float]) -> float:
        mid = len(seq) // 2
        if len(seq) % 2 == 1:
            return seq[mid]
        return (seq[mid - 1] + seq[mid]) / 2.0

    mid = n // 2
    if n % 2 == 1:
        lower = sorted_values[:mid]
        upper = sorted_values[mid + 1:]
    else:
        lower = sorted_values[:mid]
        upper = sorted_values[mid:]
    return median(lower), median(upper)


def iqr_bounds(values: List[float]) -> Tuple[Optional[float], Optional[float]]:
    q1, q3 = _quartiles(values)
    if q1 is None or q3 is None:
        return None, None
    iqr = q3 - q1
    return q1 - 1.5 * iqr, q3 + 1.5 * iqr


def iqr_outlier(value: float, lower: Optional[float], upper: Optional[float]) -> bool:
    if lower is None or upper is None:
        return False
    return value < lower or value > upper


def percentile_score(value: float, values: List[float]) -> float:
    if not values:
        return 0.0
    count = sum(1 for v in values if v <= value)
    return (count / len(values)) * 100.0


def mad_median(values: List[float]) -> Tuple[float, float]:
    if not values:
        return 0.0, 0.0
    median = statistics.median(values)
    deviations = [abs(v - median) for v in values]
    return median, statistics.median(deviations)


def score_anomalies(values: List[float], *, method: str = "zscore") -> dict:
    if not values:
        return {}
    if method not in ("zscore", "iqr"):
        raise ValueError("method must be 'zscore' or 'iqr'")

    scores: dict = {}
    if method == "zscore":
        mean = statistics.mean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0.0
        if std > 0:
            for index, value in enumerate(values):
                z = abs(value - mean) / std
                if z > DEFAULT_Z_THRESHOLD:
                    scores[index] = z
    else:
        lower, upper = iqr_bounds(values)
        if lower is not None:
            for index, value in enumerate(values):
                if value < lower:
                    scores[index] = lower - value
                elif value > upper:
                    scores[index] = value - upper
    return scores
