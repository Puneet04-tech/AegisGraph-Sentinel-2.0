"""
Machine Learning Model Management & A/B Testing Platform.

A production-grade ML model management module for versioning, deployment,
experiments, and A/B testing of fraud detection models.

Modules:
    - Model Registry: Version control and metadata
    - Model Deployment: Deployment lifecycle management
    - Experiment Tracker: Experiment tracking and comparison
    - A/B Testing: Controlled experiments and traffic splitting
"""

from .models import (
    ModelStatus,
    ModelType,
    DeploymentStatus,
    ExperimentStatus,
    ABTestStatus,
    MLModel,
    ModelDeployment,
    Experiment,
    ABTest,
    ModelMetric,
    DriftDetection,
)
from .store import MLModelStore, get_ml_store
from .model_registry import ModelRegistry, get_model_registry
from .model_deployment import ModelDeploymentManager, get_deployment_manager
from .experiment_tracker import ExperimentTracker, get_experiment_tracker
from .ab_testing import ABTestingEngine, get_ab_testing_engine

__all__ = [
    # Enums
    "ModelStatus",
    "ModelType",
    "DeploymentStatus",
    "ExperimentStatus",
    "ABTestStatus",
    # Models
    "MLModel",
    "ModelDeployment",
    "Experiment",
    "ABTest",
    "ModelMetric",
    "DriftDetection",
    # Store
    "MLModelStore",
    "get_ml_store",
    # Modules
    "ModelRegistry",
    "get_model_registry",
    "ModelDeploymentManager",
    "get_deployment_manager",
    "ExperimentTracker",
    "get_experiment_tracker",
    "ABTestingEngine",
    "get_ab_testing_engine",
]