"""Unit tests for src/data/quality.py."""

import pytest

from src.data.quality import (
    completeness,
    null_rate,
    outlier_ratio,
    report,
    uniqueness,
    value_ranges,
)


def test_completeness_all_present_returns_one():
    data = [{"name": "a", "amount": 1}, {"name": "b", "amount": 2}]
    assert completeness(data, ["name", "amount"]) == 1.0


def test_completeness_all_missing_returns_zero():
    data = [{"name": None}, {"name": ""}]
    assert completeness(data, ["name"]) == 0.0


def test_completeness_missing_field_counts_as_incomplete():
    data = [{"name": "a"}, {"amount": 3}]
    assert completeness(data, ["name", "amount"]) == 0.5


def test_completeness_partial_and_empty_string_treated_missing():
    data = [
        {"name": "a", "amount": ""},
        {"name": "b", "amount": 5},
        {"name": None, "amount": 6},
    ]
    assert completeness(data, ["name"]) == pytest.approx(2 / 3)
    assert completeness(data, ["amount"]) == pytest.approx(2 / 3)


def test_completeness_empty_data_returns_zero():
    assert completeness([], ["name"]) == 0.0


def test_uniqueness_all_unique_returns_one():
    data = [{"id": 1}, {"id": 2}, {"id": 3}]
    assert uniqueness(data, ["id"]) == 1.0


def test_uniqueness_with_duplicates_below_one():
    data = [{"id": 1}, {"id": 1}, {"id": 2}]
    assert uniqueness(data, ["id"]) == pytest.approx(2 / 3)


def test_uniqueness_empty_data_returns_zero():
    assert uniqueness([], ["id"]) == 0.0


def test_uniqueness_composite_key_fields():
    data = [
        {"acct": "a", "device": "x"},
        {"acct": "a", "device": "y"},
        {"acct": "a", "device": "x"},
        {"acct": "b", "device": "x"},
    ]
    assert uniqueness(data, ["acct", "device"]) == pytest.approx(3 / 4)
    assert uniqueness(data, ["acct"]) == pytest.approx(1 / 2)


def test_value_ranges_min_max_with_negatives():
    data = [
        {"v": -5},
        {"v": 10.5},
        {"v": None},
        {"v": "not-a-number"},
        {"v": 0},
    ]
    assert value_ranges(data, "v") == {"min": -5.0, "max": 10.5}


def test_value_ranges_empty_returns_none():
    assert value_ranges([], "v") == {"min": None, "max": None}


def test_value_ranges_ignores_boolean_values():
    data = [{"v": 1}, {"v": True}]
    assert value_ranges(data, "v") == {"min": 1.0, "max": 1.0}


def test_null_rate_partial():
    data = [{"v": 1}, {"v": None}, {"v": ""}, {}]
    assert null_rate(data, "v") == pytest.approx(0.75)


def test_null_rate_full():
    data = [{"v": None}, {"v": ""}]
    assert null_rate(data, "v") == 1.0


def test_null_rate_none_missing():
    data = [{"v": 1}, {"v": 2}]
    assert null_rate(data, "v") == 0.0


def test_outlier_ratio_single_extreme_value():
    data = [{"v": 5.0}] * 50 + [{"v": 100.0}]
    assert outlier_ratio(data, "v") == pytest.approx(1 / 51)
    assert outlier_ratio(data, "v") < 0.1


def test_outlier_ratio_constant_column_returns_zero():
    data = [{"v": 7}] * 10
    assert outlier_ratio(data, "v") == 0.0


def test_outlier_ratio_empty_returns_zero():
    assert outlier_ratio([], "v") == 0.0


def test_outlier_ratio_respects_custom_threshold():
    data = [{"v": 1}] * 4 + [{"v": 50}]
    assert outlier_ratio(data, "v", z_threshold=0.5) == pytest.approx(1 / 5)


def test_report_structure_and_values():
    data = [
        {"acct": "a", "amount": 100},
        {"acct": "a", "amount": None},
        {"acct": "b", "amount": 200},
    ]
    result = report(data, required_fields=["acct", "amount"], numeric_fields=["amount"])

    assert result["row_count"] == 3
    assert result["completeness"]["overall"] == pytest.approx(5 / 6)
    assert result["completeness"]["by_field"]["acct"] == 1.0
    assert result["completeness"]["by_field"]["amount"] == pytest.approx(2 / 3)
    assert result["uniqueness"]["key_fields"] == ["acct", "amount"]
    assert result["uniqueness"]["unique_ratio"] == 1.0
    assert result["null_rates"] == {"acct": 0.0, "amount": pytest.approx(1 / 3)}
    assert result["value_ranges"]["amount"] == {"min": 100.0, "max": 200.0}
    assert result["outlier_ratios"]["amount"] == 0.0


def test_report_empty_dataset_returns_zero_metrics():
    result = report([], required_fields=["acct"], numeric_fields=["amount"])
    assert result["row_count"] == 0
    assert result["completeness"]["overall"] == 0.0
    assert result["uniqueness"]["unique_ratio"] == 0.0
    assert result["value_ranges"]["amount"] == {"min": None, "max": None}
    assert result["outlier_ratios"]["amount"] == 0.0
