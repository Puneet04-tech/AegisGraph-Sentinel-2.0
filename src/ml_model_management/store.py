"""
ML Model Management Storage Engine.

Thread-safe storage for models, experiments, deployments, and A/B tests.
"""

from threading import Lock
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    MLModel,
    ModelDeployment,
    Experiment,
    ABTest,
    ModelMetric,
    DriftDetection,
    ModelStatus,
)

logger = logging.getLogger(__name__)


class MLModelStore:
    """Thread-safe storage for ML models and experiments.
    
    Provides:
        - O(1) lookup by ID
        - Thread-safe operations
        - Model lifecycle management
    """
    
    def __init__(self):
        """Initialize the ML model store."""
        self._lock = Lock()
        
        # Models
        self._models: Dict[str, MLModel] = {}
        
        # Deployments
        self._deployments: Dict[str, ModelDeployment] = {}
        
        # Experiments
        self._experiments: Dict[str, Experiment] = {}
        
        # A/B Tests
        self._ab_tests: Dict[str, ABTest] = {}
        
        # Metrics
        self._metrics: Dict[str, List[ModelMetric]] = {}
        
        # Drift detections
        self._drift_detections: Dict[str, DriftDetection] = {}
        
        # Initialize defaults
        self._initialize_defaults()
    
    def _initialize_defaults(self):
        """Initialize default models."""
        default_models = [
            MLModel(
                name="Fraud Detection v1",
                version="1.0.0",
                model_type="FRAUD_DETECTION",
                description="Baseline fraud detection model",
                framework="sklearn",
                parameters={"threshold": 0.5, "max_features": 100},
                metrics={"accuracy": 0.95, "precision": 0.92, "recall": 0.89},
                status=ModelStatus.PRODUCTION,
            ),
            MLModel(
                name="Risk Scoring v1",
                version="1.0.0",
                model_type="RISK_SCORING",
                description="Baseline risk scoring model",
                framework="xgboost",
                parameters={"max_depth": 6, "learning_rate": 0.1},
                metrics={"auc": 0.92, "f1": 0.88},
                status=ModelStatus.PRODUCTION,
            ),
        ]
        
        for model in default_models:
            self._models[model.model_id] = model
    
    # Model Methods
    def store_model(self, model: MLModel) -> MLModel:
        """Store a model."""
        with self._lock:
            self._models[model.model_id] = model
        return model
    
    def get_model(self, model_id: str) -> Optional[MLModel]:
        """Get model by ID."""
        return self._models.get(model_id)
    
    def get_all_models(self) -> List[MLModel]:
        """Get all models."""
        return list(self._models.values())
    
    def get_models_by_type(self, model_type: str) -> List[MLModel]:
        """Get models by type."""
        return [m for m in self._models.values() if m.model_type.value == model_type]
    
    def get_production_models(self) -> List[MLModel]:
        """Get production models."""
        return [m for m in self._models.values() if m.status == ModelStatus.PRODUCTION]
    
    def delete_model(self, model_id: str) -> bool:
        """Delete a model."""
        with self._lock:
            if model_id in self._models:
                del self._models[model_id]
                return True
        return False
    
    # Deployment Methods
    def store_deployment(self, deployment: ModelDeployment) -> ModelDeployment:
        """Store a deployment."""
        with self._lock:
            self._deployments[deployment.deployment_id] = deployment
        return deployment
    
    def get_deployment(self, deployment_id: str) -> Optional[ModelDeployment]:
        """Get deployment by ID."""
        return self._deployments.get(deployment_id)
    
    def get_model_deployments(self, model_id: str) -> List[ModelDeployment]:
        """Get deployments for a model."""
        return [d for d in self._deployments.values() if d.model_id == model_id]
    
    def get_active_deployments(self) -> List[ModelDeployment]:
        """Get active deployments."""
        return [d for d in self._deployments.values() if d.status.value in ["DEPLOYED", "DEPLOYING"]]
    
    # Experiment Methods
    def store_experiment(self, experiment: Experiment) -> Experiment:
        """Store an experiment."""
        with self._lock:
            self._experiments[experiment.experiment_id] = experiment
        return experiment
    
    def get_experiment(self, experiment_id: str) -> Optional[Experiment]:
        """Get experiment by ID."""
        return self._experiments.get(experiment_id)
    
    def get_all_experiments(self) -> List[Experiment]:
        """Get all experiments."""
        return list(self._experiments.values())
    
    def get_recent_experiments(self, limit: int = 50) -> List[Experiment]:
        """Get recent experiments."""
        experiments = list(self._experiments.values())
        return sorted(experiments, key=lambda e: e.created_at, reverse=True)[:limit]
    
    # A/B Test Methods
    def store_ab_test(self, test: ABTest) -> ABTest:
        """Store an A/B test."""
        with self._lock:
            self._ab_tests[test.test_id] = test
        return test
    
    def get_ab_test(self, test_id: str) -> Optional[ABTest]:
        """Get A/B test by ID."""
        return self._ab_tests.get(test_id)
    
    def get_all_ab_tests(self) -> List[ABTest]:
        """Get all A/B tests."""
        return list(self._ab_tests.values())
    
    def get_running_ab_tests(self) -> List[ABTest]:
        """Get running A/B tests."""
        return [t for t in self._ab_tests.values() if t.status.value == "RUNNING"]
    
    # Metric Methods
    def store_metric(self, metric: ModelMetric) -> ModelMetric:
        """Store a metric."""
        with self._lock:
            if metric.model_id not in self._metrics:
                self._metrics[metric.model_id] = []
            self._metrics[metric.model_id].append(metric)
        return metric
    
    def get_model_metrics(self, model_id: str, limit: int = 100) -> List[ModelMetric]:
        """Get metrics for a model."""
        metrics = self._metrics.get(model_id, [])
        return sorted(metrics, key=lambda m: m.timestamp, reverse=True)[:limit]
    
    # Drift Detection Methods
    def store_drift_detection(self, detection: DriftDetection) -> DriftDetection:
        """Store drift detection."""
        with self._lock:
            self._drift_detections[detection.detection_id] = detection
        return detection
    
    def get_recent_drift_detections(self, model_id: str = None, limit: int = 50) -> List[DriftDetection]:
        """Get recent drift detections."""
        detections = list(self._drift_detections.values())
        if model_id:
            detections = [d for d in detections if d.model_id == model_id]
        return sorted(detections, key=lambda d: d.timestamp, reverse=True)[:limit]
    
    # Statistics
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        return {
            "models_stored": len(self._models),
            "production_models": len(self.get_production_models()),
            "deployments_stored": len(self._deployments),
            "active_deployments": len(self.get_active_deployments()),
            "experiments_stored": len(self._experiments),
            "ab_tests_stored": len(self._ab_tests),
            "running_ab_tests": len(self.get_running_ab_tests()),
            "drift_detections_stored": len(self._drift_detections),
        }


# Global singleton
_ml_store: Optional[MLModelStore] = None


def get_ml_store() -> MLModelStore:
    """Get or create the singleton ML model store instance."""
    global _ml_store
    
    if _ml_store is None:
        _ml_store = MLModelStore()
    return _ml_store