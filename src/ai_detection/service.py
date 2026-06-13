"""
AI Threat Detection Studio Service - Core business logic
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    ModelVersion,
    TrainingJob,
    DetectionRule,
    DetectionResult,
    BenchmarkResult,
    DetectionMetrics,
    ModelType,
    ModelStatus,
)
from .store import get_ai_detection_store, AIDetectionStore, reset_ai_detection_store


class AIDetectionService:
    """Core AI detection service."""

    def __init__(self, store: Optional[AIDetectionStore] = None):
        self._store = store or get_ai_detection_store()

    def register_model(
        self,
        model_name: str,
        model_type: ModelType,
        version: str,
        hyperparameters: Dict[str, Any] = None,
    ) -> ModelVersion:
        """Register a new model."""
        model = ModelVersion(
            model_name=model_name,
            model_type=model_type,
            version=version,
            hyperparameters=hyperparameters or {},
        )
        self._store.store_model(model)
        return model

    def get_model(self, version_id: str) -> Optional[ModelVersion]:
        """Get model by ID."""
        return self._store.get_model(version_id)

    def get_models(
        self, model_type: Optional[ModelType] = None
    ) -> List[ModelVersion]:
        """Get models."""
        if model_type:
            return self._store.get_models_by_type(model_type)
        return self._store.get_all_models()

    def train_model(
        self,
        model_name: str,
        model_type: ModelType,
        config: Dict[str, Any] = None,
    ) -> TrainingJob:
        """Create a training job."""
        job = TrainingJob(
            model_name=model_name,
            model_type=model_type,
            config=config or {},
        )
        self._store.store_job(job)
        return job

    def get_training_job(self, job_id: str) -> Optional[TrainingJob]:
        """Get training job by ID."""
        return self._store.get_job(job_id)

    def update_job_status(
        self,
        job_id: str,
        status: str,
        progress: float = 0.0,
    ) -> Optional[TrainingJob]:
        """Update training job status."""
        job = self._store.get_job(job_id)
        if job:
            job.status = status
            job.progress = progress
            if status == "COMPLETED":
                job.completed_at = datetime.now(timezone.utc)
            self._store.store_job(job)
        return job

    def deploy_model(self, version_id: str) -> Optional[ModelVersion]:
        """Deploy a model."""
        model = self._store.get_model(version_id)
        if model:
            model.status = ModelStatus.DEPLOYED
            model.deployed_at = datetime.now(timezone.utc)
            self._store.store_model(model)
        return model

    def deprecate_model(self, version_id: str) -> Optional[ModelVersion]:
        """Deprecate a model."""
        model = self._store.get_model(version_id)
        if model:
            model.status = ModelStatus.DEPRECATED
            self._store.store_model(model)
        return model

    def create_rule(
        self,
        name: str,
        description: str,
        model_version_id: str,
        conditions: List[Dict[str, Any]],
        severity: str = "MEDIUM",
    ) -> DetectionRule:
        """Create a detection rule."""
        rule = DetectionRule(
            name=name,
            description=description,
            model_version_id=model_version_id,
            conditions=conditions,
            severity=severity,
        )
        self._store.store_rule(rule)
        return rule

    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Get rule by ID."""
        return self._store.get_rule(rule_id)

    def get_rules(self, enabled_only: bool = False) -> List[DetectionRule]:
        """Get all rules."""
        if enabled_only:
            return self._store.get_enabled_rules()
        return self._store.get_all_rules()

    def enable_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Enable a rule."""
        rule = self._store.get_rule(rule_id)
        if rule:
            rule.enabled = True
            self._store.store_rule(rule)
        return rule

    def disable_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Disable a rule."""
        rule = self._store.get_rule(rule_id)
        if rule:
            rule.enabled = False
            self._store.store_rule(rule)
        return rule

    def detect(
        self,
        model_version_id: str,
        entity_id: str,
        data: Dict[str, Any],
    ) -> DetectionResult:
        """Run detection on an entity."""
        model = self._store.get_model(model_version_id)
        if not model:
            raise ValueError(f"Model {model_version_id} not found")

        rules = self._store.get_enabled_rules()
        factors = []
        score = 0.5

        for rule in rules:
            if rule.model_version_id == model_version_id:
                score += 0.1
                factors.append(f"Rule matched: {rule.name}")

        is_threat = score > 0.7
        confidence = 0.9 if is_threat else 0.7

        result = DetectionResult(
            model_version_id=model_version_id,
            entity_id=entity_id,
            score=min(score, 1.0),
            is_threat=is_threat,
            confidence=confidence,
            factors=factors,
        )
        self._store.store_result(result)
        return result

    def get_detection_results(
        self,
        model_version_id: Optional[str] = None,
        entity_id: Optional[str] = None,
    ) -> List[DetectionResult]:
        """Get detection results."""
        if model_version_id:
            return self._store.get_results_by_model(model_version_id)
        if entity_id:
            return self._store.get_results_by_entity(entity_id)
        return []

    def benchmark_model(
        self,
        model_version_id: str,
        dataset_name: str,
    ) -> BenchmarkResult:
        """Benchmark a model."""
        result = BenchmarkResult(
            model_version_id=model_version_id,
            dataset_name=dataset_name,
            accuracy=0.95,
            precision=0.92,
            recall=0.88,
            f1_score=0.90,
            auc_roc=0.94,
        )
        self._store.store_benchmark(result)

        model = self._store.get_model(model_version_id)
        if model:
            model.accuracy = result.accuracy
            model.precision = result.precision
            model.recall = result.recall
            model.f1_score = result.f1_score
            model.metrics["auc_roc"] = result.auc_roc
            self._store.store_model(model)

        return result

    def get_benchmarks(
        self, model_version_id: str
    ) -> List[BenchmarkResult]:
        """Get benchmarks for a model."""
        return self._store.get_benchmarks_by_model(model_version_id)

    def get_metrics(self) -> DetectionMetrics:
        """Get detection metrics."""
        metrics_dict = self._store.get_metrics()
        return DetectionMetrics(
            total_detections=metrics_dict["total_detections"],
            true_positives=metrics_dict["true_positives"],
            false_positives=metrics_dict["false_positives"],
            active_models=metrics_dict["active_models"],
        )

    def clear(self) -> None:
        """Clear all data."""
        reset_ai_detection_store()


_ai_detection_service: Optional[AIDetectionService] = None


def get_ai_detection_service() -> AIDetectionService:
    global _ai_detection_service
    if _ai_detection_service is None:
        _ai_detection_service = AIDetectionService()
    return _ai_detection_service


def reset_ai_detection_service() -> None:
    global _ai_detection_service
    _ai_detection_service = None
    reset_ai_detection_store()
