"""Feature aggregation helpers for behavior and velocity feature pipelines.

Pure-numeric transforms that never raise on degenerate inputs: missing values
collapse to safe defaults and empty sequences yield zeros so downstream model
features stay finite.
"""

import statistics


def zscore(value, mean, std):
    if value is None or mean is None or std is None:
        return 0.0
    if std == 0:
        return 0.0
    return (value - mean) / std


def min_max_scale(value, low, high):
    if value is None or low is None or high is None:
        return 0.0
    if high == low:
        return 1.0 if value == high else 0.0
    return (value - low) / (high - low)


def clip(value, low, high):
    if value is None:
        return 0.0
    return min(max(value, low), high)


def binned(value, edges):
    if value is None or not edges:
        return -1
    ordered = sorted(edges)
    if value < ordered[0]:
        return 0
    if value > ordered[-1]:
        return len(ordered)
    for index, edge in enumerate(ordered):
        if value <= edge:
            return index
    return len(ordered)


def ratio(numerator, denominator):
    if numerator is None or denominator is None:
        return None
    if denominator == 0:
        return None
    return numerator / denominator


def mean_std(values):
    cleaned = [v for v in values if v is not None]
    if not cleaned:
        return (0.0, 0.0)
    return (statistics.fmean(cleaned), statistics.pstdev(cleaned))


def max_min(values):
    cleaned = [v for v in values if v is not None]
    if not cleaned:
        return (0.0, 0.0)
    return (float(max(cleaned)), float(min(cleaned)))


def summarize_features(values, edges=None):
    cleaned = [v for v in values if v is not None]
    result = {
        "count": float(len(cleaned)),
        "sum": float(sum(cleaned)),
        "mean": statistics.fmean(cleaned) if cleaned else 0.0,
        "min": float(min(cleaned)) if cleaned else 0.0,
        "max": float(max(cleaned)) if cleaned else 0.0,
        "std": statistics.pstdev(cleaned) if cleaned else 0.0,
    }
    if edges is not None:
        bins = {}
        for value in cleaned:
            index = binned(value, edges)
            bins[index] = bins.get(index, 0) + 1
        result["bins"] = bins
    return result
