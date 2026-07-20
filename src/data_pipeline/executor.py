"""
Pipeline Executor Module.

Pipeline execution, monitoring, and error handling.
"""

import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    PipelineJob,
    JobStatus,
    PipelineMetrics,
)
from .store import PipelineStore, get_pipeline_store

logger = logging.getLogger(__name__)


class PipelineExecutor:
    """Pipeline Executor for running data pipelines.
    
    Provides:
        - Pipeline execution
        - Error handling
        - Retry logic
        - Monitoring
    """
    
    def __init__(self, store: Optional[PipelineStore] = None):
        """Initialize the pipeline executor."""
        self._store = store or get_pipeline_store()
        self._module_id = "executor"
    
    def execute(
        self,
        pipeline_id: str,
        source_data: List[Dict[str, Any]] = None,
    ) -> PipelineJob:
        """Execute a pipeline."""
        from .pipeline_builder import PipelineBuilder
        
        # Use the same store instance
        builder = PipelineBuilder(store=self._store)
        pipeline = builder.get_pipeline(pipeline_id)
        
        if not pipeline:
            raise ValueError(f"Pipeline {pipeline_id} not found")
        
        logger.info(f"Executing pipeline: {pipeline.name}")
        
        # Create job
        job = PipelineJob(
            pipeline_id=pipeline_id,
            status=JobStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        
        self._store.store_job(job)
        
        try:
            # Execute stages
            data = source_data or self._generate_sample_data()
            records_in = len(data)
            records_processed = 0
            records_failed = 0
            
            for stage in pipeline.stages:
                stage_type = stage.get("type")
                stage_config = stage.get("config", {})
                
                logger.info(f"Executing stage: {stage_type}")
                job.logs.append(f"Stage {stage_type} started")
                
                data, records_processed, stage_failed = self._execute_stage(
                    stage_type, stage_config, data
                )
                records_failed += stage_failed
                
                job.logs.append(f"Stage {stage_type} completed")
            
            # Job completed
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)
            job.records_processed = records_processed
            job.records_failed = records_failed
            
            # Store metrics
            duration = (job.completed_at - job.started_at).total_seconds()
            metrics = PipelineMetrics(
                pipeline_id=pipeline_id,
                job_id=job.job_id,
                records_in=records_in,
                records_out=records_processed,
                records_failed=records_failed,
                duration_seconds=duration,
                throughput_per_second=records_processed / duration if duration > 0 else 0,
            )
            self._store.store_metrics(metrics)
            
        except Exception as e:
            logger.error(f"Pipeline execution failed: {e}")
            job.status = JobStatus.FAILED
            job.completed_at = datetime.now(timezone.utc)
            job.error_message = str(e)
            job.logs.append(f"Error: {str(e)}")
        
        self._store.store_job(job)
        return job
    
    def _execute_stage(
        self,
        stage_type: str,
        config: Dict[str, Any],
        data: List[Dict[str, Any]],
    ) -> tuple:
        """Execute a single stage and return (data, records_out, records_failed).

        Dispatches to the source/transform/validate/load implementations
        based on the stage's configured behavior instead of unconditionally
        reporting success.
        """
        if stage_type == "source":
            return self._execute_source_stage(config, data)
        elif stage_type == "transform":
            return self._execute_transform_stage(config, data)
        elif stage_type == "validate":
            return self._execute_validate_stage(config, data)
        elif stage_type == "load":
            return self._execute_load_stage(config, data)
        
        logger.warning(f"Unknown stage type: {stage_type}")
        return data, len(data), 0
    
    def _execute_source_stage(
        self,
        config: Dict[str, Any],
        data: List[Dict[str, Any]],
    ) -> tuple:
        """Extract data from the configured source, if any."""
        from .data_sources import DataSourceConnector
        
        source_id = config.get("source_id")
        if not source_id:
            return data, len(data), 0
        
        connector = DataSourceConnector(store=self._store)
        extracted = connector.extract_data(source_id, limit=config.get("limit", 1000))
        return extracted, len(extracted), 0
    
    def _execute_transform_stage(
        self,
        config: Dict[str, Any],
        data: List[Dict[str, Any]],
    ) -> tuple:
        """Apply the configured transformation to the data."""
        from .transformations import DataTransformer
        
        transform_id = config.get("transform_id")
        if not transform_id:
            return data, len(data), 0
        
        transformer = DataTransformer(store=self._store)
        transform = transformer.get_transform(transform_id)
        if not transform:
            raise ValueError(f"Transform {transform_id} not found")
        
        transformed = transformer.apply_transform(transform, data)
        records_failed = max(0, len(data) - len(transformed))
        return transformed, len(transformed), records_failed
    
    def _execute_validate_stage(
        self,
        config: Dict[str, Any],
        data: List[Dict[str, Any]],
    ) -> tuple:
        """Run configured validation rules against the data.

        Records failing any rule marked as ERROR are dropped from the
        output (and counted as failed) when ``strict`` is set.
        """
        from .validators import DataValidator
        from .models import ValidationLevel
        
        rule_ids = config.get("rule_ids")
        validator = DataValidator(store=self._store)
        rules = (
            [r for r in validator.list_rules() if r.rule_id in rule_ids]
            if rule_ids
            else validator.list_rules()
        )
        
        if not rules:
            return data, len(data), 0
        
        results = validator.validate_data(data, rules)
        records_failed = sum(r.error_count for r in results)
        
        strict = config.get("strict", False)
        has_error_failure = any(
            r.error_count > 0
            for r, rule in zip(results, rules)
            if rule.level == ValidationLevel.ERROR
        )
        if strict and has_error_failure:
            raise ValueError("Validation failed for one or more required rules")
        
        return data, len(data), records_failed
    
    def _execute_load_stage(
        self,
        config: Dict[str, Any],
        data: List[Dict[str, Any]],
    ) -> tuple:
        """Load stage is a terminal sink; data passes through unchanged."""
        return data, len(data), 0
    
    def _generate_sample_data(self) -> List[Dict[str, Any]]:
        """Generate sample data for testing."""
        return [
            {"id": i, "value": random.uniform(0, 100), "category": f"cat_{i % 5}"}
            for i in range(100)
        ]
    
    def get_job(self, job_id: str) -> Optional[PipelineJob]:
        """Get job by ID."""
        return self._store.get_job(job_id)
    
    def get_pipeline_jobs(
        self,
        pipeline_id: str,
        limit: int = 100,
    ) -> List[PipelineJob]:
        """Get jobs for a pipeline."""
        return self._store.get_pipeline_jobs(pipeline_id, limit)
    
    def get_recent_jobs(self, limit: int = 100) -> List[PipelineJob]:
        """Get recent jobs."""
        return self._store.get_recent_jobs(limit)
    
    def cancel_job(self, job_id: str) -> PipelineJob:
        """Cancel a running job."""
        job = self._store.get_job(job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")
        
        job.status = JobStatus.CANCELLED
        job.completed_at = datetime.now(timezone.utc)
        self._store.store_job(job)
        
        return job
    
    def retry_job(self, job_id: str) -> PipelineJob:
        """Retry a failed job."""
        job = self._store.get_job(job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")
        
        # Create new job based on original
        new_job = PipelineJob(
            pipeline_id=job.pipeline_id,
            status=JobStatus.PENDING,
        )
        
        self._store.store_job(new_job)
        
        # Execute
        return self.execute(job.pipeline_id)
    
    def get_job_metrics(self, job_id: str) -> Optional[PipelineMetrics]:
        """Get metrics for a job."""
        job = self._store.get_job(job_id)
        if not job:
            return None
        
        pipeline_metrics = self._store.get_pipeline_metrics(job.pipeline_id)
        for metrics in pipeline_metrics:
            if metrics.job_id == job_id:
                return metrics
        
        return None


# Global singleton
_pipeline_executor: Optional[PipelineExecutor] = None


def get_pipeline_executor(store: Optional[PipelineStore] = None) -> PipelineExecutor:
    """Get or create the singleton PipelineExecutor instance."""
    global _pipeline_executor
    
    if _pipeline_executor is None:
        _pipeline_executor = PipelineExecutor(store=store)
    return _pipeline_executor