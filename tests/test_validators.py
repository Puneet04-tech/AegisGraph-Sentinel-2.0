"""Dedicated unit tests for src/data_pipeline/validators.py.

``DataValidator`` rule evaluation, schema checks and quality scoring had no
direct regression coverage.  These tests pin the not_null / range / pattern /
in_list / unique rule semantics, the schema validator and the quality-score
penalties.
"""

import pytest

from src.data_pipeline.validators import DataValidator
from src.data_pipeline.store import PipelineStore


@pytest.fixture
def validator() -> DataValidator:
    return DataValidator(store=PipelineStore())


def test_create_rule_persists(validator):
    rule = validator.create_rule("email required", "email", "not_null")
    assert validator.get_rule(rule.rule_id) is rule
    assert validator.list_rules() == [rule]


def test_not_null_rule_flags_empty_and_missing(validator):
    rule = validator.create_rule("email required", "email", "not_null")
    data = [
        {"id": "1", "email": "a@b.com"},
        {"id": "2", "email": ""},
        {"id": "3"},
    ]
    (result,) = validator.validate_data(data, [rule])
    assert result.error_count == 2
    assert result.passed is False


def test_range_rule_flags_out_of_bounds(validator):
    rule = validator.create_rule(
        "amount range", "amount", "range", {"min": 0, "max": 1000}
    )
    data = [{"id": "1", "amount": 500}, {"id": "2", "amount": 5000}]
    (result,) = validator.validate_data(data, [rule])
    assert result.error_count == 1


def test_pattern_rule_rejects_mismatch(validator):
    rule = validator.create_rule(
        "iso date", "ts", "pattern", {"pattern": r"\d{4}-\d{2}-\d{2}"}
    )
    data = [{"id": "1", "ts": "2025-01-01"}, {"id": "2", "ts": "nope"}]
    (result,) = validator.validate_data(data, [rule])
    assert result.error_count == 1


def test_in_list_rule_rejects_unknown_value(validator):
    rule = validator.create_rule(
        "status whitelist", "status", "in_list", {"allowed": ["active", "suspended"]}
    )
    data = [{"id": "1", "status": "active"}, {"id": "2", "status": "deleted"}]
    (result,) = validator.validate_data(data, [rule])
    assert result.error_count == 1


def test_unique_rule_flags_duplicates(validator):
    rule = validator.create_rule("txn unique", "txn_id", "unique")
    data = [{"id": "1", "txn_id": "T1"}, {"id": "2", "txn_id": "T1"}]
    (result,) = validator.validate_data(data, [rule])
    assert result.error_count == 2


def test_validate_schema_reports_missing_and_extra(validator):
    data = [{"email": "a@b.com", "extra": True}]
    result = validator.validate_schema(data, ["id", "email"])
    assert result["valid"] is False
    assert any("Missing" in e for e in result["errors"])
    assert any("Extra" in e for e in result["errors"])


def test_validate_schema_exact_match_is_valid(validator):
    data = [{"id": "1", "email": "a@b.com"}]
    result = validator.validate_schema(data, ["id", "email"])
    assert result["valid"] is True
    assert result["errors"] == []


def test_check_quality_empty_data(validator):
    result = validator.check_quality([])
    assert result["quality_score"] == 0
    assert "No data" in result["issues"]


def test_check_quality_penalizes_high_null_rate(validator):
    data = [{"id": i, "email": "" if i % 2 else "a@b.com"} for i in range(10)]
    result = validator.check_quality(data)
    assert result["quality_score"] == 80
    assert result["total_records"] == 10
