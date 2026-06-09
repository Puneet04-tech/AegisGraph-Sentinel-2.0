"""
Tests for Data Pipeline & ETL Engine.

Comprehensive tests for:
    - Pipeline Builder
    - Data Sources
    - Transformations
    - Validators
    - Executor
"""

import pytest
from datetime import datetime, timezone

from src.data_pipeline import (
    SourceType,
    TransformType,
    ValidationLevel,
    PipelineStatus,
    JobStatus,
    PipelineStore,
    PipelineBuilder,
    DataSourceConnector,
    DataTransformer,
    DataValidator,
    PipelineExecutor,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def store():
    """Create a fresh pipeline store for testing."""
    return PipelineStore()


@pytest.fixture
def pipeline_builder(store):
    """Create a pipeline builder."""
    return PipelineBuilder(store=store)


@pytest.fixture
def data_sources(store):
    """Create a data source connector."""
    return DataSourceConnector(store=store)


@pytest.fixture
def transformer(store):
    """Create a data transformer."""
    return DataTransformer(store=store)


@pytest.fixture
def validator(store):
    """Create a data validator."""
    return DataValidator(store=store)


@pytest.fixture
def executor(store):
    """Create a pipeline executor."""
    return PipelineExecutor(store=store)


# =============================================================================
# Store Tests
# =============================================================================

class TestPipelineStore:
    """Tests for PipelineStore."""
    
    def test_get_stats(self, store):
        """Test getting store statistics."""
        stats = store.get_stats()
        
        assert "pipelines_stored" in stats
        assert "sources_stored" in stats


# =============================================================================
# Pipeline Builder Tests
# =============================================================================

class TestPipelineBuilder:
    """Tests for PipelineBuilder."""
    
    def test_create_pipeline(self, pipeline_builder):
        """Test creating a pipeline."""
        pipeline = pipeline_builder.create_pipeline(
            name="Test Pipeline",
            description="Test pipeline description",
        )
        
        assert pipeline.pipeline_id is not None
        assert pipeline.name == "Test Pipeline"
    
    def test_add_stage(self, pipeline_builder):
        """Test adding a stage to pipeline."""
        pipeline = pipeline_builder.create_pipeline(
            name="Stage Test",
            description="Test",
        )
        
        updated = pipeline_builder.add_stage(
            pipeline_id=pipeline.pipeline_id,
            stage_type="source",
            config={"type": "database"},
        )
        
        assert len(updated.stages) == 1
    
    def test_get_pipeline_templates(self, pipeline_builder):
        """Test getting pipeline templates."""
        templates = pipeline_builder.get_pipeline_templates()
        
        assert len(templates) >= 3
        assert any(t["id"] == "etl_basic" for t in templates)


# =============================================================================
# Data Source Tests
# =============================================================================

class TestDataSource:
    """Tests for DataSourceConnector."""
    
    def test_create_source(self, data_sources):
        """Test creating a data source."""
        source = data_sources.create_source(
            name="Test Source",
            source_type=SourceType.DATABASE,
            connection_config={"host": "localhost"},
        )
        
        assert source.source_id is not None
        assert source.name == "Test Source"
    
    def test_list_sources(self, data_sources):
        """Test listing sources."""
        sources = data_sources.list_sources()
        
        assert isinstance(sources, list)
    
    def test_discover_schema(self, data_sources):
        """Test schema discovery."""
        source = data_sources.create_source(
            name="Schema Test",
            source_type=SourceType.DATABASE,
            connection_config={},
        )
        
        schema = data_sources.discover_schema(source.source_id)
        
        assert "tables" in schema or "endpoints" in schema
    
    def test_extract_data(self, data_sources):
        """Test data extraction."""
        source = data_sources.create_source(
            name="Extract Test",
            source_type=SourceType.API,
            connection_config={},
        )
        
        data = data_sources.extract_data(source.source_id)
        
        assert isinstance(data, list)


# =============================================================================
# Transformer Tests
# =============================================================================

class TestTransformer:
    """Tests for DataTransformer."""
    
    def test_create_transform(self, transformer):
        """Test creating a transformation."""
        transform = transformer.create_transform(
            name="Test Transform",
            transform_type=TransformType.MAP,
            config={"field_mappings": {"old": "new"}},
        )
        
        assert transform.transform_id is not None
    
    def test_apply_map_transform(self, transformer):
        """Test applying map transformation."""
        transform = transformer.create_transform(
            name="Map Test",
            transform_type=TransformType.MAP,
            config={
                "field_mappings": {"a": "x", "b": "y"},
                "computed_fields": {"sum": "a+b"},
            },
        )
        
        data = [{"a": 10, "b": 20}, {"a": 5, "b": 15}]
        result = transformer.apply_transform(transform, data)
        
        assert len(result) == 2
        assert "x" in result[0]
    
    def test_apply_filter_transform(self, transformer):
        """Test applying filter transformation."""
        transform = transformer.create_transform(
            name="Filter Test",
            transform_type=TransformType.FILTER,
            config={
                "conditions": [
                    {"field": "value", "operator": "gt", "value": 50}
                ]
            },
        )
        
        data = [{"id": 1, "value": 30}, {"id": 2, "value": 70}]
        result = transformer.apply_transform(transform, data)
        
        assert len(result) == 1
        assert result[0]["id"] == 2


# =============================================================================
# Validator Tests
# =============================================================================

class TestValidator:
    """Tests for DataValidator."""
    
    def test_create_rule(self, validator):
        """Test creating a validation rule."""
        rule = validator.create_rule(
            name="Test Rule",
            field="email",
            rule_type="pattern",
            config={"pattern": r".+@.+\..+"},
        )
        
        assert rule.rule_id is not None
    
    def test_validate_data(self, validator):
        """Test validating data."""
        rule = validator.create_rule(
            name="Not Null Test",
            field="name",
            rule_type="not_null",
        )
        
        data = [{"name": "John"}, {"name": None}, {"name": "Jane"}]
        results = validator.validate_data(data, [rule])
        
        assert len(results) == 1
        assert results[0].error_count == 1
    
    def test_check_quality(self, validator):
        """Test checking data quality."""
        data = [
            {"id": 1, "value": 100},
            {"id": 2, "value": 200},
            {"id": 3, "value": None},
        ]
        
        quality = validator.check_quality(data)
        
        assert "quality_score" in quality


# =============================================================================
# Executor Tests
# =============================================================================

class TestExecutor:
    """Tests for PipelineExecutor."""
    
    def test_execute_pipeline(self, executor, pipeline_builder):
        """Test executing a pipeline."""
        pipeline = pipeline_builder.create_pipeline(
            name="Execute Test",
            description="Test",
            stages=[
                {"type": "source", "config": {}},
                {"type": "transform", "config": {}},
            ],
        )
        
        job = executor.execute(pipeline.pipeline_id)
        
        assert job.job_id is not None
        assert job.status in [JobStatus.COMPLETED, JobStatus.FAILED]
    
    def test_get_recent_jobs(self, executor):
        """Test getting recent jobs."""
        jobs = executor.get_recent_jobs()
        
        assert isinstance(jobs, list)


# =============================================================================
# Integration Tests
# =============================================================================

class TestPipelineIntegration:
    """Integration tests for pipeline workflow."""
    
    def test_full_pipeline_workflow(
        self,
        pipeline_builder,
        data_sources,
        transformer,
        validator,
        executor,
    ):
        """Test full pipeline workflow."""
        # 1. Create source
        source = data_sources.create_source(
            name="Integration Source",
            source_type=SourceType.DATABASE,
            connection_config={"host": "localhost"},
        )
        
        # 2. Create transform
        transform = transformer.create_transform(
            name="Integration Transform",
            transform_type=TransformType.MAP,
            config={"field_mappings": {"id": "record_id"}},
        )
        
        # 3. Create validation rule
        rule = validator.create_rule(
            name="Integration Rule",
            field="value",
            rule_type="not_null",
        )
        
        # 4. Create pipeline
        pipeline = pipeline_builder.create_pipeline(
            name="Integration Pipeline",
            description="Full integration test",
            stages=[
                {"type": "source", "config": {"source_id": source.source_id}},
                {"type": "transform", "config": {"transform_id": transform.transform_id}},
            ],
        )
        
        # 5. Execute pipeline
        job = executor.execute(pipeline.pipeline_id)
        
        # Verify
        assert source.source_id is not None
        assert transform.transform_id is not None
        assert rule.rule_id is not None
        assert pipeline.pipeline_id is not None
        assert job.job_id is not None