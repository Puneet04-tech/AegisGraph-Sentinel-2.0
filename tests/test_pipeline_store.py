"""Dedicated unit tests for src/data_pipeline/store.py.

``PipelineStore`` is the thread-safe ETL backbone (pipelines, sources,
transforms, validation rules/results, jobs and metrics) but has no dedicated
unit coverage.  These tests pin the full CRUD surface, active-pipeline
filtering, default sources and job/metric lookups.
"""

import pytest

from datetime import datetime

from src.data_pipeline.store import PipelineStore
from src.data_pipeline.models import (
    DataSource,
    DataTransformation,
    JobStatus,
    Pipeline,
    PipelineJob,
    PipelineMetrics,
    PipelineStatus,
    SourceType,
    TransformType,
    ValidationLevel,
    ValidationResult,
    ValidationRule,
)


@pytest.fixture
def store() -> PipelineStore:
    return PipelineStore()


def test_default_sources_present(store):
    sources = store.get_all_sources()
    assert len(sources) == 2
    assert store.get_source(sources[0].source_id) is sources[0]


def test_pipeline_crud_and_active_filter(store):
    active = store.store_pipeline(Pipeline(name="a", description="", status=PipelineStatus.ACTIVE))
    draft = store.store_pipeline(Pipeline(name="b", description="", status=PipelineStatus.DRAFT))
    assert store.get_pipeline(active.pipeline_id) is active
    assert set(p.pipeline_id for p in store.get_all_pipelines()) == {active.pipeline_id, draft.pipeline_id}
    assert store.get_active_pipelines() == [active]
    assert store.delete_pipeline(active.pipeline_id) is True
    assert store.get_pipeline(active.pipeline_id) is None
    assert store.delete_pipeline("missing") is False


def test_source_and_transform_storage(store):
    source = store.store_source(DataSource(name="s3", source_type=SourceType.FILE))
    assert store.get_source(source.source_id) is source
    transform = store.store_transform(DataTransformation(name="t", transform_type=TransformType.MAP))
    assert store.get_transform(transform.transform_id) is transform
    assert store.get_all_transforms() == [transform]


def test_validation_rule_and_result_storage(store):
    rule = store.store_validation_rule(ValidationRule(name="r", field="email", rule_type="not_null"))
    assert store.get_validation_rule(rule.rule_id) is rule
    assert store.get_all_validation_rules() == [rule]
    result = store.store_validation_result(ValidationResult(rule_id=rule.rule_id, passed=False, record_count=2, error_count=1))
    assert store.get_validation_result(result.result_id) is result


def test_jobs_sorted_by_start_desc(store):
    old = store.store_job(PipelineJob(pipeline_id="p1", status=JobStatus.COMPLETED, started_at=datetime(2025, 1, 1)))
    new = store.store_job(PipelineJob(pipeline_id="p1", status=JobStatus.RUNNING, started_at=datetime(2025, 1, 2)))
    assert store.get_job(old.job_id) is old
    recent = store.get_recent_jobs(10)
    assert recent[0].job_id == new.job_id
    assert store.get_pipeline_jobs("p1")[0].job_id == new.job_id


def test_metrics_scoped_by_pipeline(store):
    m1 = store.store_metrics(PipelineMetrics(pipeline_id="p1", records_in=10, records_out=8))
    store.store_metrics(PipelineMetrics(pipeline_id="p1", records_in=5, records_out=5))
    store.store_metrics(PipelineMetrics(pipeline_id="p2"))
    assert len(store.get_pipeline_metrics("p1")) == 2
    assert len(store.get_pipeline_metrics("p2")) == 1
    assert store.get_pipeline_metrics("missing") == []
    assert m1.records_in == 10


def test_get_stats_counts(store):
    store.store_pipeline(Pipeline(name="a", description=""))
    stats = store.get_stats()
    assert stats["pipelines_stored"] == 1
    assert stats["sources_stored"] == 2
