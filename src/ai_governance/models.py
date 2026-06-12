"""
AI Governance Models
Enterprise AI governance and model security models.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class ModelStatus(Enum):
    """Model operational status."""
    DEVELOPMENT = "DEVELOPMENT"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"
    DEPRECATED = "DEPRECATED"
    ARCHIVED = "ARCHIVED"


class ModelRisk(Enum):
    """Model risk levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class BiasMetric(Enum):
    """Bias detection metrics."""
    DEMOGRAPHIC_PARITY = "DEMOGRAPHIC_PARITY"
    EQUALIZED_ODDS = "EQUALIZED_ODDS"
    DISPARATE_IMPACT = "DISPARATE_IMPACT"
    CALIBRATION = "CALIBRATION"


class DriftType(Enum):
    """Types of model drift."""
    CONCEPT_DRIFT = "CONCEPT_DRIFT"
    DATA_DRIFT = "DATA_DRIFT"
    PREDICTION_DRIFT = "PREDICTION_DRIFT"


@dataclass
class Model:
    """AI model in the registry."""
    model_id: str
    name: str
    version: str
    model_type: str
    status: ModelStatus = ModelStatus.DEVELOPMENT
    risk_level: ModelRisk = ModelRisk.MEDIUM
    description: str = ""
    framework: str = ""
    owner: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    deployed_at: Optional[datetime] = None
    metrics: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "name": self.name,
            "version": self.version,
            "model_type": self.model_type,
            "status": self.status.value,
            "risk_level": self.risk_level.value,
            "description": self.description,
            "framework": self.framework,
            "owner": self.owner,
            "created_at": self.created_at.isoformat(),
            "deployed_at": self.deployed_at.isoformat() if self.deployed_at else None,
            "metrics": self.metrics,
            "metadata": self.metadata,
        }


@dataclass
class ModelDrift:
    """Model drift detection result."""
    drift_id: str
    model_id: str
    drift_type: DriftType
    drift_score: float
    severity: str
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "drift_id": self.drift_id,
            "model_id": self.model_id,
            "drift_type": self.drift_type.value,
            "drift_score": self.drift_score,
            "severity": self.severity,
            "detected_at": self.detected_at.isoformat(),
            "details": self.details,
        }


@dataclass
class BiasReport:
    """Bias detection report."""
    report_id: str
    model_id: str
    metric: BiasMetric
    score: float
    threshold: float
    is_fair: bool
    affected_groups: List[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "model_id": self.model_id,
            "metric": self.metric.value,
            "score": self.score,
            "threshold": self.threshold,
            "is_fair": self.is_fair,
            "affected_groups": self.affected_groups,
            "generated_at": self.generated_at.isoformat(),
        }


@dataclass
class ModelExplanation:
    """Model explanation result."""
    explanation_id: str
    model_id: str
    prediction_id: str
    feature_importance: Dict[str, float]
    explanation_method: str
    confidence: float
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "explanation_id": self.explanation_id,
            "model_id": self.model_id,
            "prediction_id": self.prediction_id,
            "feature_importance": self.feature_importance,
            "explanation_method": self.explanation_method,
            "confidence": self.confidence,
            "generated_at": self.generated_at.isoformat(),
        }


@dataclass
class AuditRecord:
    """AI audit record."""
    audit_id: str
    model_id: str
    action: str
    user: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "model_id": self.model_id,
            "action": self.action,
            "user": self.user,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }