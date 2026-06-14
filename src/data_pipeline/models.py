"""
Data Pipeline & ETL Engine Models.

Data models for pipelines, sources, transformations, and validators.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid


class PipelineStatus(str, Enum):
    """Pipeline status."""
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    FAILED = "FAILED"


class JobStatus(str, Enum):
    """Pipeline job status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class SourceType(str, Enum):
    """Data source types."""
    DATABASE = "DATABASE"
    API = "API"
    FILE = "FILE"
    STREAM = "STREAM"


class TransformType(str, Enum):
    """Transformation types."""
    MAP = "MAP"
    FILTER = "FILTER"
    AGGREGATE = "AGGREGATE"
    JOIN = "JOIN"
    DEDUP = "DEDUP"
    CUSTOM = "CUSTOM"


class ValidationLevel(str, Enum):
    """Validation levels."""
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class Pipeline(BaseModel):
    """Data pipeline configuration."""
    pipeline_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    status: PipelineStatus = PipelineStatus.DRAFT
    stages: List[Dict[str, Any]] = Field(default_factory=list)
    schedule: Optional[str] = None  # cron expression
    timeout_seconds: int = 3600
    retry_count: int = 3
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DataSource(BaseModel):
    """Data source configuration."""
    source_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    source_type: SourceType
    connection_config: Dict[str, Any] = Field(default_factory=dict)
    schema: Dict[str, Any] = Field(default_factory=dict)
    incremental_field: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DataTransformation(BaseModel):
    """Data transformation configuration."""
    transform_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    transform_type: TransformType
    config: Dict[str, Any] = Field(default_factory=dict)
    order: int = 0


class ValidationRule(BaseModel):
    """Data validation rule."""
    rule_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    field: str
    rule_type: str  # not_null, unique, range, pattern, custom
    config: Dict[str, Any] = Field(default_factory=dict)
    level: ValidationLevel = ValidationLevel.ERROR


class ValidationResult(BaseModel):
    """Data validation result."""
    result_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    passed: bool
    record_count: int
    error_count: int
    error_samples: List[Dict[str, Any]] = Field(default_factory=list)
    validated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PipelineJob(BaseModel):
    """Pipeline execution job."""
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pipeline_id: str
    status: JobStatus = JobStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    records_processed: int = 0
    records_failed: int = 0
    error_message: Optional[str] = None
    logs: List[str] = Field(default_factory=list)


class PipelineMetrics(BaseModel):
    """Pipeline execution metrics."""
    metrics_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pipeline_id: str
    job_id: Optional[str] = None
    records_in: int = 0
    records_out: int = 0
    records_failed: int = 0
    duration_seconds: float = 0.0
    throughput_per_second: float = 0.0
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))