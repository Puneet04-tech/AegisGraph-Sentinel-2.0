"""
AI Threat Detection Studio Store - Thread-safe storage
"""

from __future__ import annotations

from threading import Lock
from typing import Any, Dict, List, Optional

from .models import (
    ModelVersion,
    TrainingJob,
    DetectionRule,
    DetectionResult,
    BenchmarkResult,
    ModelType,
    ModelStatus,
)


class AIDetectionStore:
    """Thread-safe storage for AI detection data."""

    def __init__(self):
        self._lock = Lock()
        self._models: Dict[str, ModelVersion] = {}
        self._jobs: Dict[str, TrainingJob] = {}
        self._rules: Dict[str, DetectionRule] = {}
        self._results: Dict[str, DetectionResult] = {}
        self._benchmarks: Dict[str, BenchmarkResult] = {}

    def store_model(self, model: ModelVersion) -> ModelVersion:
        with self._lock:
            self._models[model.version_id] = model
        return model

    def get_model(self, version_id: str) -> Optional[ModelVersion]:
        return self._models.get(version_id)

    def get_models_by_type(
        self, model_type: ModelType
    ) -> List[ModelVersion]:
        return [m for m in self._models.values() if m.model_type == model_type]

    def get_all_models(self) -> List[ModelVersion]:
        return list(self._models.values())

    def store_job(self, job: TrainingJob) -> TrainingJob:
        with self._lock:
            self._jobs[job.job_id] = job
        return job

    def get_job(self, job_id: str) -> Optional[TrainingJob]:
        return self._jobs.get(job_id)

    def get_jobs_by_status(self, status: str) -> List[TrainingJob]:
        return [j for j in self._jobs.values() if j.status == status]

    def store_rule(self, rule: DetectionRule) -> DetectionRule:
        with self._lock:
            self._rules[rule.rule_id] = rule
        return rule

    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        return self._rules.get(rule_id)

    def get_all_rules(self) -> List[DetectionRule]:
        return list(self._rules.values())

    def get_enabled_rules(self) -> List[DetectionRule]:
        return [r for r in self._rules.values() if r.enabled]

    def store_result(self, result: DetectionResult) -> DetectionResult:
        with self._lock:
            self._results[result.result_id] = result
        return result

    def get_results_by_model(
        self, model_version_id: str
    ) -> List[DetectionResult]:
        return [
            r for r in self._results.values()
            if r.model_version_id == model_version_id
        ]

    def get_results_by_entity(self, entity_id: str) -> List[DetectionResult]:
        return [r for r in self._results.values() if r.entity_id == entity_id]

    def store_benchmark(self, result: BenchmarkResult) -> BenchmarkResult:
        with self._lock:
            self._benchmarks[result.benchmark_id] = result
        return result

    def get_benchmarks_by_model(
        self, model_version_id: str
    ) -> List[BenchmarkResult]:
        return [
            b for b in self._benchmarks.values()
            if b.model_version_id == model_version_id
        ]

    def get_metrics(self) -> Dict[str, Any]:
        models = list(self._models.values())
        results = list(self._results.values())
        true_positives = len([r for r in results if r.is_threat])
        false_positives = len([r for r in results if not r.is_threat])

        return {
            "total_models": len(models),
            "active_models": len([m for m in models if m.status == ModelStatus.DEPLOYED]),
            "total_detections": len(results),
            "true_positives": true_positives,
            "false_positives": false_positives,
        }


_ai_detection_store: Optional[AIDetectionStore] = None
_store_lock = Lock()


def get_ai_detection_store() -> AIDetectionStore:
    global _ai_detection_store
    with _store_lock:
        if _ai_detection_store is None:
            _ai_detection_store = AIDetectionStore()
        return _ai_detection_store


def reset_ai_detection_store() -> None:
    global _ai_detection_store
    with _store_lock:
        _ai_detection_store = AIDetectionStore()
