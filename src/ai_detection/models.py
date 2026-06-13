"""
AI Threat Detection Studio - Data Models

Comprehensive AI threat detection platform.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class ModelType(str, Enum):
    """Model types."""
    FRAUD_DETECTION = "FRAUD_DETECTION"
    THREAT_DETECTION = "THREAT_DETECTION"
    ANOMALY_DETECTION = "ANOMALY_DETECTION"
    INSIDER_THREAT = "INSIDER_THREAT"
    COMPLIANCE = "COMPLIANCE"


class ModelStatus(str, Enum):
    """Model status."""
    TRAINING = "TRAINING"
    VALIDATED = "VALIDATED"
    DEPLOYED = "DEPLOYED"
    DEPRECATED = "DEPRECATED"
    FAILED = "FAILED"


class ModelVersion(BaseModel):
    """Model version."""
    version_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_name: str
    model_type: ModelType
    version: str
    status: ModelStatus = ModelStatus.TRAINING
    metrics: Dict[str, float] = Field(default_factory=dict)
    hyperparameters: Dict[str, Any] = Field(default_factory=dict)
    trained_at: Optional[datetime] = None
    deployed_at: Optional[datetime] = None
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TrainingJob(BaseModel):
    """Training job."""
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_name: str
    model_type: ModelType
    status: str = "PENDING"
    config: Dict[str, Any] = Field(default_factory=dict)
    progress: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None


class DetectionRule(BaseModel):
    """Detection rule."""
    rule_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    model_version_id: str
    conditions: List[Dict[str, Any]] = Field(default_factory=list)
    severity: str = "MEDIUM"
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DetectionResult(BaseModel):
    """Detection result."""
    result_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_version_id: str
    entity_id: str
    score: float = 0.0
    is_threat: bool = False
    confidence: float = 0.0
    factors: List[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BenchmarkResult(BaseModel):
    """Benchmark result."""
    benchmark_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_version_id: str
    dataset_name: str
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    auc_roc: float = 0.0
    benchmarked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DetectionMetrics(BaseModel):
    """Detection metrics."""
    total_detections: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    avg_detection_time_ms: float = 0.0
    active_models: int = 0
