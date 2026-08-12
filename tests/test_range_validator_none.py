"""Range validation must not crash on None values (Issue #3512).

The range rule compared the record value against min/max with ``>=``/``<=``
without guarding ``None``, raising ``TypeError`` and aborting the whole
validation pass. None must now fail the range check cleanly instead of
crashing.
"""

import pytest

from src.data_pipeline.validators import DataValidator


class TestRangeValidatorNone:
    def test_none_value_fails_range_cleanly(self):
        validator = DataValidator()
        rule = validator.create_rule(
            name="amount range",
            field="amount",
            rule_type="range",
            config={"min": 0, "max": 1000},
        )
        data = [{"id": 1, "amount": None}]

        results = validator.validate_data(data, rules=[rule])
        result = results[0]

        assert result.error_count == 1
        assert result.passed is False
        assert result.error_samples[0]["value"] is None

    def test_none_mixed_with_valid_values(self):
        validator = DataValidator()
        rule = validator.create_rule(
            name="amount range",
            field="amount",
            rule_type="range",
            config={"min": 0, "max": 1000},
        )
        data = [
            {"id": 1, "amount": 500},
            {"id": 2, "amount": None},
            {"id": 3, "amount": 42},
        ]

        results = validator.validate_data(data, rules=[rule])
        result = results[0]

        assert result.error_count == 1
        assert result.record_count == 3
        assert result.passed is False

    def test_range_without_bounds_accepts_none(self):
        validator = DataValidator()
        rule = validator.create_rule(
            name="open range",
            field="amount",
            rule_type="range",
            config={},
        )
        data = [{"id": 1, "amount": None}]

        results = validator.validate_data(data, rules=[rule])
        result = results[0]

        assert result.error_count == 0
        assert result.passed is True
