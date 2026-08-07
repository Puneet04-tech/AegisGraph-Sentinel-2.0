"""Data quality assessment utilities for tabular record batches.

Each function reduces a list of record dicts to a single quality metric:
completeness, uniqueness, value ranges, null rates and outlier ratios.
The ``report`` helper combines them into one structure suitable for
monitoring, data drift checks and pipeline gate decisions.
"""

from __future__ import annotations

import math
from typing import Any


def _is_missing(value: Any) -> bool:
    """True for null, empty string or explicitly missing values."""
    return value is None or value == ""


def _numeric_values(data, field):
    values = []
    for row in data:
        value = row.get(field)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            values.append(float(value))
    return values


def completeness(data, required_fields):
    """Fraction (0.0-1.0) of required field cells that hold a value.

    A cell counts as missing when the field is absent from the row or its
    value is None/empty string.
    """
    if not data or not required_fields:
        return 0.0
    total = len(data) * len(required_fields)
    present = sum(
        1
        for row in data
        for field in required_fields
        if field in row and not _is_missing(row[field])
    )
    return present / total


def uniqueness(data, key_fields):
    """Fraction (0.0-1.0) of rows whose key tuple is distinct."""
    if not data or not key_fields:
        return 0.0
    keys = {tuple(row.get(field) for field in key_fields) for row in data}
    return len(keys) / len(data)


def value_ranges(data, field):
    """Min/max of numeric values for a field, ignoring None and strings."""
    values = _numeric_values(data, field)
    if not values:
        return {"min": None, "max": None}
    return {"min": min(values), "max": max(values)}


def null_rate(data, field):
    """Fraction (0.0-1.0) of rows where the field is missing/empty."""
    if not data:
        return 0.0
    missing = sum(
        1 for row in data if field not in row or _is_missing(row[field])
    )
    return missing / len(data)


def outlier_ratio(data, field, *, z_threshold=3.0):
    """Fraction of numeric values with |z-score| above the threshold.

    Uses population standard deviation. Constant or empty columns yield
    0.0 because the z-score is undefined there.
    """
    values = _numeric_values(data, field)
    if not values:
        return 0.0
    n = len(values)
    mean = sum(values) / n
    std = math.sqrt(sum((v - mean) ** 2 for v in values) / n)
    if std == 0:
        return 0.0
    outliers = sum(
        1 for v in values if abs(v - mean) / std > z_threshold
    )
    return outliers / n


def report(data, required_fields, numeric_fields):
    """Aggregate data quality metrics into a single report dict.

    Structure::

        {
            "row_count": int,
            "completeness": {"overall": float, "by_field": {field: float}},
            "uniqueness": {"key_fields": [field], "unique_ratio": float},
            "null_rates": {field: float},
            "value_ranges": {field: {"min": float|None, "max": float|None}},
            "outlier_ratios": {field: float},
        }
    """
    return {
        "row_count": len(data),
        "completeness": {
            "overall": completeness(data, required_fields),
            "by_field": {f: completeness(data, [f]) for f in required_fields},
        },
        "uniqueness": {
            "key_fields": list(required_fields),
            "unique_ratio": uniqueness(data, required_fields),
        },
        "null_rates": {f: null_rate(data, f) for f in required_fields},
        "value_ranges": {f: value_ranges(data, f) for f in numeric_fields},
        "outlier_ratios": {f: outlier_ratio(data, f) for f in numeric_fields},
    }
