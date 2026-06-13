"""
Research Laboratory Models
AI-powered security research environment.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class ExperimentStatus(Enum):
    """Experiment status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ModelType(Enum):
    """Model types for research."""
    FRAUD_DETECTOR = "FRAUD_DETECTOR"
    THREAT_MODEL = "THREAT_MODEL"
    AML_CLASSIFIER = "AML_CLASSIFIER"
    ANOMALY_DETECTOR = "ANOMALY_DETECTOR"
    RISK_SCORER = "RISK_SCORER"
    GRAPH_ANALYZER = "GRAPH_ANALYZER"


class BenchmarkType(Enum):
    """Benchmark types."""
    ACCURACY = "ACCURACY"
    PRECISION = "PRECISION"
    RECALL = "RECALL"
    F1_SCORE = "F1_SCORE"
    LATENCY = "LATENCY"
    THROUGHPUT = "THROUGHPUT"


@dataclass
class ResearchExperiment:
    """A research experiment."""
    experiment_id: str
    name: str
    description: str
    model_type: ModelType
    status: ExperimentStatus = ExperimentStatus.PENDING
    parameters: Dict[str, Any] = field(default_factory=dict)
    results: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_by: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "name": self.name,
            "description": self.description,
            "model_type": self.model_type.value,
            "status": self.status.value,
            "parameters": self.parameters,
            "results": self.results,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_by": self.created_by,
        }


@dataclass
class BenchmarkResult:
    """Benchmark result."""
    benchmark_id: str
    experiment_id: str
    benchmark_type: BenchmarkType
    score: float
    baseline_score: float
    improvement: float
    dataset: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "benchmark_id": self.benchmark_id,
            "experiment_id": self.experiment_id,
            "benchmark_type": self.benchmark_type.value,
            "score": self.score,
            "baseline_score": self.baseline_score,
            "improvement": self.improvement,
            "dataset": self.dataset,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class ModelEvaluation:
    """Model evaluation result."""
    evaluation_id: str
    model_id: str
    model_version: str
    metrics: Dict[str, float]
    performance_score: float
    recommendations: List[str]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "evaluation_id": self.evaluation_id,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "metrics": self.metrics,
            "performance_score": self.performance_score,
            "recommendations": self.recommendations,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class Dataset:
    """Research dataset."""
    dataset_id: str
    name: str
    description: str
    size: int
    features: List[str]
    labels: List[str]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "name": self.name,
            "description": self.description,
            "size": self.size,
            "features": self.features,
            "labels": self.labels,
            "created_at": self.created_at.isoformat(),
        }