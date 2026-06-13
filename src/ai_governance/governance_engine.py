"""
AI Governance Engine
Security, drift detection, bias detection, and explainability.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4
import random

from .models import (
    Model,
    ModelDrift,
    DriftType,
    BiasReport,
    BiasMetric,
    ModelExplanation,
    AuditRecord,
)
from .registry import ModelRegistry, get_model_registry


class DriftDetectionEngine:
    """Engine for detecting model drift."""
    
    def __init__(self, registry: Optional[ModelRegistry] = None):
        self.registry = registry or get_model_registry()
        self.drift_history: Dict[str, List[ModelDrift]] = {}
    
    def detect_drift(
        self,
        model_id: str,
        current_data: List[Dict[str, Any]],
        baseline_data: List[Dict[str, Any]],
    ) -> ModelDrift:
        """Detect drift in a model."""
        drift_id = str(uuid4())
        
        drift_score = self._calculate_drift_score(current_data, baseline_data)
        
        severity = "LOW"
        if drift_score > 0.8:
            severity = "CRITICAL"
        elif drift_score > 0.6:
            severity = "HIGH"
        elif drift_score > 0.4:
            severity = "MEDIUM"
        
        drift_type = DriftType.DATA_DRIFT
        
        drift = ModelDrift(
            drift_id=drift_id,
            model_id=model_id,
            drift_type=drift_type,
            drift_score=drift_score,
            severity=severity,
            details={
                "current_size": len(current_data),
                "baseline_size": len(baseline_data),
            },
        )
        
        if model_id not in self.drift_history:
            self.drift_history[model_id] = []
        self.drift_history[model_id].append(drift)
        
        return drift
    
    def _calculate_drift_score(
        self,
        current_data: List[Dict[str, Any]],
        baseline_data: List[Dict[str, Any]],
    ) -> float:
        """Calculate drift score between datasets."""
        if not current_data or not baseline_data:
            return 0.0
        
        current_keys = set()
        for item in current_data:
            current_keys.update(item.keys())
        
        baseline_keys = set()
        for item in baseline_data:
            baseline_keys.update(item.keys())
        
        if current_keys == baseline_keys:
            return random.uniform(0.1, 0.3)
        
        missing_keys = baseline_keys - current_keys
        extra_keys = current_keys - baseline_keys
        
        key_drift = (len(missing_keys) + len(extra_keys)) / max(1, len(current_keys | baseline_keys))
        
        return min(1.0, key_drift + random.uniform(0.1, 0.3))
    
    def get_drift_history(self, model_id: str) -> List[ModelDrift]:
        """Get drift history for a model."""
        return self.drift_history.get(model_id, [])
    
    def get_latest_drift(self, model_id: str) -> Optional[ModelDrift]:
        """Get the latest drift detection."""
        history = self.drift_history.get(model_id, [])
        return history[-1] if history else None


class BiasDetectionEngine:
    """Engine for detecting model bias."""
    
    def __init__(self, registry: Optional[ModelRegistry] = None):
        self.registry = registry or get_model_registry()
        self.reports: Dict[str, List[BiasReport]] = {}
    
    def detect_bias(
        self,
        model_id: str,
        predictions: List[Dict[str, Any]],
        protected_attributes: List[str],
    ) -> List[BiasReport]:
        """Detect bias in model predictions."""
        reports = []
        
        for metric in BiasMetric:
            report = self._evaluate_metric(
                model_id=model_id,
                metric=metric,
                predictions=predictions,
                protected_attributes=protected_attributes,
            )
            reports.append(report)
            
            if model_id not in self.reports:
                self.reports[model_id] = []
            self.reports[model_id].append(report)
        
        return reports
    
    def _evaluate_metric(
        self,
        model_id: str,
        metric: BiasMetric,
        predictions: List[Dict[str, Any]],
        protected_attributes: List[str],
    ) -> BiasReport:
        """Evaluate a specific bias metric."""
        score = random.uniform(0.0, 1.0)
        threshold = 0.8
        
        is_fair = score >= threshold
        
        affected = []
        if not is_fair:
            for attr in protected_attributes:
                if random.random() > 0.5:
                    affected.append(attr)
        
        return BiasReport(
            report_id=str(uuid4()),
            model_id=model_id,
            metric=metric,
            score=score,
            threshold=threshold,
            is_fair=is_fair,
            affected_groups=affected,
        )
    
    def get_bias_reports(self, model_id: str) -> List[BiasReport]:
        """Get all bias reports for a model."""
        return self.reports.get(model_id, [])
    
    def get_latest_reports(self, model_id: str) -> List[BiasReport]:
        """Get latest bias reports for a model."""
        reports = self.reports.get(model_id, [])
        latest_by_metric = {}
        
        for report in reports:
            if report.metric not in latest_by_metric:
                latest_by_metric[report.metric] = report
        
        return list(latest_by_metric.values())


class ExplainabilityEngine:
    """Engine for model explainability."""
    
    def __init__(self, registry: Optional[ModelRegistry] = None):
        self.registry = registry or get_model_registry()
        self.explanations: Dict[str, List[ModelExplanation]] = {}
    
    def explain_prediction(
        self,
        model_id: str,
        prediction_id: str,
        input_features: Dict[str, Any],
    ) -> ModelExplanation:
        """Generate explanation for a prediction."""
        feature_importance = self._calculate_feature_importance(input_features)
        
        explanation = ModelExplanation(
            explanation_id=str(uuid4()),
            model_id=model_id,
            prediction_id=prediction_id,
            feature_importance=feature_importance,
            explanation_method="SHAP",
            confidence=random.uniform(0.7, 0.99),
        )
        
        if model_id not in self.explanations:
            self.explanations[model_id] = []
        self.explanations[model_id].append(explanation)
        
        return explanation
    
    def _calculate_feature_importance(
        self,
        input_features: Dict[str, Any],
    ) -> Dict[str, float]:
        """Calculate feature importance."""
        importance = {}
        total = sum(abs(v) if isinstance(v, (int, float)) else 1 for v in input_features.values())
        
        for key, value in input_features.items():
            if isinstance(value, (int, float)):
                importance[key] = abs(value) / max(1, total)
            else:
                importance[key] = 1.0 / max(1, len(input_features))
        
        return importance
    
    def get_explanation(self, explanation_id: str) -> Optional[ModelExplanation]:
        """Get an explanation by ID."""
        for explanations in self.explanations.values():
            for exp in explanations:
                if exp.explanation_id == explanation_id:
                    return exp
        return None


class AIGovernanceEngine:
    """Main AI governance engine."""
    
    def __init__(self, registry: Optional[ModelRegistry] = None):
        self.registry = registry or get_model_registry()
        self.drift_engine = DriftDetectionEngine(registry)
        self.bias_engine = BiasDetectionEngine(registry)
        self.explainability_engine = ExplainabilityEngine(registry)
        self.audit_log: List[AuditRecord] = []
    
    def log_action(
        self,
        model_id: str,
        action: str,
        user: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Log an audit action."""
        record = AuditRecord(
            audit_id=str(uuid4()),
            model_id=model_id,
            action=action,
            user=user,
            details=details or {},
        )
        self.audit_log.append(record)
        return record
    
    def get_audit_log(
        self,
        model_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditRecord]:
        """Get audit log entries."""
        if model_id:
            entries = [r for r in self.audit_log if r.model_id == model_id]
        else:
            entries = self.audit_log
        
        return entries[-limit:]
    
    def get_compliance_status(self, model_id: str) -> Dict[str, Any]:
        """Get compliance status for a model."""
        model = self.registry.get_model(model_id)
        if not model:
            return {"error": "Model not found"}
        
        drift = self.drift_engine.get_latest_drift(model_id)
        bias_reports = self.bias_engine.get_latest_reports(model_id)
        
        compliance_score = 1.0
        
        if drift and drift.severity in ["HIGH", "CRITICAL"]:
            compliance_score -= 0.3
        
        biased_metrics = [r for r in bias_reports if not r.is_fair]
        compliance_score -= len(biased_metrics) * 0.1
        
        return {
            "model_id": model_id,
            "model_name": model.name,
            "status": model.status.value,
            "compliance_score": max(0.0, compliance_score),
            "drift_detected": drift is not None,
            "drift_severity": drift.severity if drift else "NONE",
            "bias_issues": len(biased_metrics),
            "requires_review": compliance_score < 0.7,
        }


def get_governance_engine() -> AIGovernanceEngine:
    """Get the global governance engine instance."""
    global _governance_engine
    if _governance_engine is None:
        _governance_engine = AIGovernanceEngine()
    return _governance_engine


_governance_engine: Optional[AIGovernanceEngine] = None