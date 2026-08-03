"""Dedicated unit tests for src/data_pipeline/transformations.py.

``DataTransformer`` applies map/filter/aggregate/dedup transforms with a safe
AST formula evaluator.  These tests pin each transform type and the formula
safety boundaries (division by zero, unknown names, over-length, power).
"""

import pytest

from src.data_pipeline.transformations import DataTransformer
from src.data_pipeline.store import PipelineStore
from src.data_pipeline.models import TransformType


@pytest.fixture
def transformer() -> DataTransformer:
    return DataTransformer(store=PipelineStore())


def test_create_transform_persists(transformer):
    transform = transformer.create_transform("double-amount", TransformType.MAP, {"computed_fields": {"total": "amount * 2"}})
    assert transformer.get_transform(transform.transform_id) is transform
    assert transformer.list_transforms() == [transform]


def test_apply_map_with_mappings_and_computed_fields(transformer):
    transform = transformer.create_transform(
        "normalize", TransformType.MAP, {"field_mappings": {"amt": "amount"}, "computed_fields": {"double": "amount * 2"}}
    )
    result = transformer.apply_transform(transform, [{"amt": 100, "status": "ok"}])
    assert result[0] == {"amount": 100, "status": "ok", "double": 200.0}


def test_apply_filter_conditions(transformer):
    transform = transformer.create_transform(
        "active-only", TransformType.FILTER, {"conditions": [{"field": "status", "operator": "eq", "value": "active"}]}
    )
    data = [{"status": "active"}, {"status": "disabled"}]
    assert transformer.apply_transform(transform, data) == [{"status": "active"}]


def test_apply_aggregate_sum_by_group(transformer):
    transform = transformer.create_transform(
        "sum-by-region", TransformType.AGGREGATE, {"group_by": ["region"], "aggregations": {"amount": "sum"}}
    )
    data = [
        {"region": "US", "amount": 10},
        {"region": "US", "amount": 20},
        {"region": "EU", "amount": 5},
    ]
    result = transformer.apply_transform(transform, data)
    assert result == [{"region": "US", "amount": 30}, {"region": "EU", "amount": 5}]


def test_apply_dedup_keeps_first(transformer):
    transform = transformer.create_transform("dedupe", TransformType.DEDUP, {"dedup_fields": ["email"]})
    data = [{"email": "a@b", "v": 1}, {"email": "a@b", "v": 2}, {"email": "c@d", "v": 3}]
    result = transformer.apply_transform(transform, data)
    assert [r["email"] for r in result] == ["a@b", "c@d"]


def test_apply_dedup_keeps_last(transformer):
    transform = transformer.create_transform("dedupe", TransformType.DEDUP, {"dedup_fields": ["email"], "keep": "last"})
    data = [{"email": "a@b", "v": 1}, {"email": "a@b", "v": 2}, {"email": "c@d", "v": 3}]
    result = transformer.apply_transform(transform, data)
    assert result == [{"email": "a@b", "v": 2}, {"email": "c@d", "v": 3}]


def test_unsupported_transform_returns_data_unchanged(transformer):
    transform = transformer.create_transform("custom", TransformType.CUSTOM, {})
    data = [{"x": 1}]
    assert transformer.apply_transform(transform, data) == data


def test_compute_value_basic_arithmetic(transformer):
    assert transformer._compute_value("amount * 2", {"amount": 100}) == 200.0
    assert transformer._compute_value("a + b", {"a": 1, "b": 2}) == 3.0
    assert transformer._compute_value("-amount", {"amount": 100}) == -100.0


def test_compute_value_safety_edges(transformer):
    assert transformer._compute_value("", {"amount": 100}) == 0.0
    assert transformer._compute_value("missing + 1", {}) == 0.0
    assert transformer._compute_value("amount / 0", {"amount": 100}) == 0.0
    assert transformer._compute_value("9**9**9", {}) == 0.0
    assert transformer._compute_value("amount * " + "1" * 300, {"amount": 2}) == 0.0
