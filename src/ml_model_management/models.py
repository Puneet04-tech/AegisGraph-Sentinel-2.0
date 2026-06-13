"""
Machine Learning Model Management Models.

Data models for models, experiments, deployments, and A/B tests.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid


class ModelStatus(str, Enum):
    """Model status."""
    REGISTERED = "REGISTERED"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"
    ARCHIVED = "ARCHIVED"
    FAILED = "FAILED"


class ModelType(str, Enum):
    """Model types."""
    FRAUD_DETECTION = "FRAUD_DETECTION"
    RISK_SCORING = "RISK_SCORING"
    ANOMALY_DETECTION = "ANOMALY_DETECTION"
    PATTERN_RECOGNITION = "PATTERN_RECOGNITION"
    ENTITY_LINKING = "ENTITY_LINKING"


class DeploymentStatus(str, Enum):
    """Deployment status."""
    PENDING = "PENDING"
    DEPLOYING = "DEPLOYING"
    DEPLOYED = "DEPLOYED"
    ROLLING_BACK = "ROLLING_BACK"
    FAILED = "FAILED"


class ExperimentStatus(str, Enum):
    """Experiment status."""
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ABTestStatus(str, Enum):
    """A/B test status."""
    DRAFT = "DRAFT"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"


class MLModel(BaseModel):
    """ML model in registry."""
    model_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    version: str
    model_type: ModelType
    description: str
    status: ModelStatus = ModelStatus.REGISTERED
    framework: str  # sklearn, tensorflow, pytorch, etc.
    parameters: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, float] = Field(default_factory=dict)
    artifact_path: Optional[str] = None
    parent_model_id: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ModelDeployment(BaseModel):
    """Model deployment configuration."""
    deployment_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_id: str
    environment: str  # staging, production
    status: DeploymentStatus = DeploymentStatus.PENDING
    traffic_percentage: float = 100.0
    config: Dict[str, Any] = Field(default_factory=dict)
    deployed_at: Optional[datetime] = None
    rolled_back_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Experiment(BaseModel):
    """ML experiment."""
    experiment_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    model_type: ModelType
    parameters: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, float] = Field(default_factory=dict)
    status: ExperimentStatus = ExperimentStatus.CREATED
    parent_experiment_id: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ABTest(BaseModel):
    """A/B test configuration."""
    test_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    model_a_id: str  # Control
    model_b_id: str   # Variant
    traffic_split: float = 0.5  # Percentage to model B
    status: ABTestStatus = ABTestStatus.DRAFT
    metrics: Dict[str, float] = Field(default_factory=dict)  # Model A metrics
    variant_metrics: Dict[str, float] = Field(default_factory=dict)  # Model B metrics
    sample_size: int = 1000
    confidence_level: float = 0.95
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    winner: Optional[str] = None  # A, B, or None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ModelMetric(BaseModel):
    """Model performance metric."""
    metric_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_id: str
    metric_name: str
    value: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DriftDetection(BaseModel):
    """Model drift detection result."""
    detection_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_id: str
    drift_type: str  # concept_drift, data_drift, model_drift
    drift_score: float
    detected: bool
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))