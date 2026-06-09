"""
Data Pipeline Storage Engine.

Thread-safe storage for pipelines, jobs, and metrics.
"""

from threading import Lock
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    Pipeline,
    DataSource,
    DataTransformation,
    ValidationRule,
    ValidationResult,
    PipelineJob,
    PipelineMetrics,
    PipelineStatus,
)

logger = logging.getLogger(__name__)


class PipelineStore:
    """Thread-safe storage for pipeline data.
    
    Provides:
        - O(1) lookup by ID
        - Thread-safe operations
        - Pipeline lifecycle management
    """
    
    def __init__(self):
        """Initialize the pipeline store."""
        self._lock = Lock()
        
        # Pipelines
        self._pipelines: Dict[str, Pipeline] = {}
        
        # Sources
        self._sources: Dict[str, DataSource] = {}
        
        # Transformations
        self._transforms: Dict[str, DataTransformation] = {}
        
        # Validation rules
        self._validation_rules: Dict[str, ValidationRule] = {}
        
        # Validation results
        self._validation_results: Dict[str, ValidationResult] = {}
        
        # Jobs
        self._jobs: Dict[str, PipelineJob] = {}
        
        # Metrics
        self._metrics: Dict[str, List[PipelineMetrics]] = {}
        
        # Initialize defaults
        self._initialize_defaults()
    
    def _initialize_defaults(self):
        """Initialize default sources."""
        default_sources = [
            DataSource(
                name="Transaction Database",
                source_type="DATABASE",
                connection_config={"host": "localhost", "port": 5432},
                schema={"tables": ["transactions", "users"]},
            ),
            DataSource(
                name="Alert API",
                source_type="API",
                connection_config={"endpoint": "https://api.example.com/alerts"},
            ),
        ]
        
        for source in default_sources:
            self._sources[source.source_id] = source
    
    # Pipeline Methods
    def store_pipeline(self, pipeline: Pipeline) -> Pipeline:
        """Store a pipeline."""
        with self._lock:
            self._pipelines[pipeline.pipeline_id] = pipeline
        return pipeline
    
    def get_pipeline(self, pipeline_id: str) -> Optional[Pipeline]:
        """Get pipeline by ID."""
        return self._pipelines.get(pipeline_id)
    
    def get_all_pipelines(self) -> List[Pipeline]:
        """Get all pipelines."""
        return list(self._pipelines.values())
    
    def get_active_pipelines(self) -> List[Pipeline]:
        """Get active pipelines."""
        return [p for p in self._pipelines.values() if p.status == PipelineStatus.ACTIVE]
    
    def delete_pipeline(self, pipeline_id: str) -> bool:
        """Delete a pipeline."""
        with self._lock:
            if pipeline_id in self._pipelines:
                del self._pipelines[pipeline_id]
                return True
        return False
    
    # Source Methods
    def store_source(self, source: DataSource) -> DataSource:
        """Store a source."""
        with self._lock:
            self._sources[source.source_id] = source
        return source
    
    def get_source(self, source_id: str) -> Optional[DataSource]:
        """Get source by ID."""
        return self._sources.get(source_id)
    
    def get_all_sources(self) -> List[DataSource]:
        """Get all sources."""
        return list(self._sources.values())
    
    # Transform Methods
    def store_transform(self, transform: DataTransformation) -> DataTransformation:
        """Store a transformation."""
        with self._lock:
            self._transforms[transform.transform_id] = transform
        return transform
    
    def get_transform(self, transform_id: str) -> Optional[DataTransformation]:
        """Get transform by ID."""
        return self._transforms.get(transform_id)
    
    def get_all_transforms(self) -> List[DataTransformation]:
        """Get all transforms."""
        return list(self._transforms.values())
    
    # Validation Rule Methods
    def store_validation_rule(self, rule: ValidationRule) -> ValidationRule:
        """Store a validation rule."""
        with self._lock:
            self._validation_rules[rule.rule_id] = rule
        return rule
    
    def get_validation_rule(self, rule_id: str) -> Optional[ValidationRule]:
        """Get validation rule by ID."""
        return self._validation_rules.get(rule_id)
    
    def get_all_validation_rules(self) -> List[ValidationRule]:
        """Get all validation rules."""
        return list(self._validation_rules.values())
    
    # Validation Result Methods
    def store_validation_result(self, result: ValidationResult) -> ValidationResult:
        """Store validation result."""
        with self._lock:
            self._validation_results[result.result_id] = result
        return result
    
    def get_validation_result(self, result_id: str) -> Optional[ValidationResult]:
        """Get validation result by ID."""
        return self._validation_results.get(result_id)
    
    # Job Methods
    def store_job(self, job: PipelineJob) -> PipelineJob:
        """Store a pipeline job."""
        with self._lock:
            self._jobs[job.job_id] = job
        return job
    
    def get_job(self, job_id: str) -> Optional[PipelineJob]:
        """Get job by ID."""
        return self._jobs.get(job_id)
    
    def get_pipeline_jobs(self, pipeline_id: str, limit: int = 100) -> List[PipelineJob]:
        """Get jobs for a pipeline."""
        jobs = [j for j in self._jobs.values() if j.pipeline_id == pipeline_id]
        return sorted(jobs, key=lambda j: j.started_at or datetime.min, reverse=True)[:limit]
    
    def get_recent_jobs(self, limit: int = 100) -> List[PipelineJob]:
        """Get recent jobs."""
        jobs = list(self._jobs.values())
        return sorted(jobs, key=lambda j: j.started_at or datetime.min, reverse=True)[:limit]
    
    # Metrics Methods
    def store_metrics(self, metrics: PipelineMetrics) -> PipelineMetrics:
        """Store pipeline metrics."""
        with self._lock:
            if metrics.pipeline_id not in self._metrics:
                self._metrics[metrics.pipeline_id] = []
            self._metrics[metrics.pipeline_id].append(metrics)
        return metrics
    
    def get_pipeline_metrics(self, pipeline_id: str, limit: int = 100) -> List[PipelineMetrics]:
        """Get metrics for a pipeline."""
        metrics = self._metrics.get(pipeline_id, [])
        return sorted(metrics, key=lambda m: m.computed_at, reverse=True)[:limit]
    
    # Statistics
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        return {
            "pipelines_stored": len(self._pipelines),
            "active_pipelines": len(self.get_active_pipelines()),
            "sources_stored": len(self._sources),
            "transforms_stored": len(self._transforms),
            "validation_rules_stored": len(self._validation_rules),
            "jobs_stored": len(self._jobs),
            "metrics_stored": sum(len(m) for m in self._metrics.values()),
        }


# Global singleton
_pipeline_store: Optional[PipelineStore] = None


def get_pipeline_store() -> PipelineStore:
    """Get or create the singleton pipeline store instance."""
    global _pipeline_store
    
    if _pipeline_store is None:
        _pipeline_store = PipelineStore()
    return _pipeline_store