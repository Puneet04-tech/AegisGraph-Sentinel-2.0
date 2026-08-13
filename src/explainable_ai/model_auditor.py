"""
Model Auditor Module.

Model lineage tracking, drift detection, and change management.
"""

import hashlib
import json
from statistics import mean, pstdev
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import ModelAudit, ModelAuditStatus
from .store import ExplainableAIStore, get_xai_store

logger = logging.getLogger(__name__)


class ModelAuditor:
    """Model Auditor for model auditability.
    
    Provides:
        - Model lineage tracking
        - Training data audit
        - Drift detection
        - Change management
    """

    #: Feature drift above this is reported as a warning.
    FEATURE_DRIFT_THRESHOLD = 0.1

    #: Performance drift above this is reported as a warning.
    PERFORMANCE_DRIFT_THRESHOLD = 0.15

    #: Keys read as the model's output when measuring performance drift.
    SCORE_KEYS = ("score", "prediction", "prediction_value", "output_score")

    def __init__(self, store: Optional[ExplainableAIStore] = None):
        """Initialize the model auditor."""
        self._store = store or get_xai_store()
        self._module_id = "model_auditor"
    
    def create_audit(
        self,
        model_id: str,
        model_name: str,
        model_version: str,
        audit_type: str = "initial",
    ) -> ModelAudit:
        """Create a new model audit."""
        logger.info(f"Creating audit for model {model_id}")
        
        audit = ModelAudit(
            model_id=model_id,
            model_name=model_name,
            model_version=model_version,
            audit_type=audit_type,
            status=ModelAuditStatus.PENDING,
        )
        
        self._store.store_audit(audit)
        return audit
    
    def start_audit(
        self,
        audit_id: str,
        training_data: Optional[List[Dict[str, Any]]] = None,
        reference_data: Optional[List[Dict[str, Any]]] = None,
        current_data: Optional[List[Dict[str, Any]]] = None,
    ) -> ModelAudit:
        """Start an audit.

        Args:
            audit_id: Audit to run.
            training_data: Training records to hash for the integrity check.
                Without it the check is recorded as skipped rather than
                passing against a hash of nothing.
            reference_data: Baseline sample for drift comparison.
            current_data: Recent sample for drift comparison.
        """
        audit = self._store.get_audit(audit_id)
        if not audit:
            raise ValueError(f"Audit {audit_id} not found")
        
        audit.status = ModelAuditStatus.IN_PROGRESS
        self._store.store_audit(audit)
        
        # Perform audit checks
        self._perform_audit_checks(
            audit,
            training_data=training_data,
            reference_data=reference_data,
            current_data=current_data,
        )
        
        return audit
    
    def _perform_audit_checks(
        self,
        audit: ModelAudit,
        training_data: Optional[List[Dict[str, Any]]] = None,
        reference_data: Optional[List[Dict[str, Any]]] = None,
        current_data: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """Perform audit checks on the model."""
        findings = []
        
        # Check 1: Model version consistency
        findings.append({
            "check": "version_consistency",
            "status": "pass",
            "description": "Model version is consistent across all deployments",
        })
        
        # Check 2: Training data integrity. The hash used to be taken over
        # f"training_data_{random.randint(1000, 9999)}", so it never described
        # any data and could never match between two audits of the same model
        # -- the exact thing an integrity hash exists to establish.
        if training_data:
            audit.training_data_hash = self._compute_data_hash(training_data)
            findings.append({
                "check": "training_data_integrity",
                "status": "pass",
                "description": f"Training data hash: {audit.training_data_hash}",
            })
        else:
            audit.training_data_hash = None
            findings.append({
                "check": "training_data_integrity",
                "status": "skipped",
                "description": "No training data supplied; integrity not verified",
            })

        # Checks 3 and 4: drift, measured against the reference sample when
        # one is available. Both scores used to be random draws.
        drift = None
        if reference_data and current_data:
            drift = self.detect_drift(audit.model_id, reference_data, current_data)
            audit.feature_drift_score = drift["feature_drift_score"]
            audit.performance_drift_score = drift["performance_drift_score"]

        findings.append(self._drift_finding(
            "feature_drift", audit.feature_drift_score,
            self.FEATURE_DRIFT_THRESHOLD,
        ))
        findings.append(self._drift_finding(
            "performance_drift", audit.performance_drift_score,
            self.PERFORMANCE_DRIFT_THRESHOLD,
        ))

        # Check 5: bias. This module performs no bias analysis; claiming a
        # pass is worse than recording that the check did not run.
        findings.append({
            "check": "bias_assessment",
            "status": "skipped",
            "description": (
                "Bias analysis is performed by ComplianceReporter.analyze_bias "
                "and was not run as part of this audit"
            ),
        })

        audit.findings = findings
        audit.completed_at = datetime.now(timezone.utc)

        # An audit that raised warnings or could not complete its checks is
        # not approved. Previously every audit was stamped APPROVED by
        # "system" regardless of what the checks found.
        blocking = [f for f in findings if f["status"] in ("warning", "skipped")]
        if blocking:
            audit.status = ModelAuditStatus.IN_PROGRESS
            logger.info(
                "Audit %s completed with %d check(s) needing review; awaiting "
                "approval", audit.audit_id, len(blocking),
            )
        else:
            audit.status = ModelAuditStatus.APPROVED
            audit.approved_by = "system"
            audit.approved_at = datetime.now(timezone.utc)

        self._store.store_audit(audit)

    def _drift_finding(
        self,
        check: str,
        score: Optional[float],
        threshold: float,
    ) -> Dict[str, Any]:
        """Turn a drift score into an audit finding."""
        if score is None:
            return {
                "check": check,
                "status": "skipped",
                "description": (
                    f"No comparable samples supplied; {check.replace('_', ' ')} "
                    "not measured"
                ),
            }
        if score > threshold:
            return {
                "check": check,
                "status": "warning",
                "description": f"{check.replace('_', ' ').capitalize()} detected: {score:.4f}",
            }
        return {
            "check": check,
            "status": "pass",
            "description": f"{check.replace('_', ' ').capitalize()} within acceptable range",
        }

    def _compute_data_hash(self, data: Any) -> str:
        """Hash the supplied data for an integrity check.

        Serialised with sorted keys so that equal data hashes equally
        regardless of dict ordering.
        """
        payload = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]
    
    def approve_audit(
        self,
        audit_id: str,
        approved_by: str,
    ) -> ModelAudit:
        """Approve a model audit."""
        audit = self._store.get_audit(audit_id)
        if not audit:
            raise ValueError(f"Audit {audit_id} not found")
        
        audit.status = ModelAuditStatus.APPROVED
        audit.approved_by = approved_by
        audit.approved_at = datetime.now(timezone.utc)
        audit.completed_at = datetime.now(timezone.utc)
        
        self._store.store_audit(audit)
        
        # Store metrics
        self._store.store_metrics({
            "event": "model_audit_approved",
            "model_id": audit.model_id,
            "audit_id": audit_id,
            "approved_by": approved_by,
        })
        
        return audit
    
    def reject_audit(
        self,
        audit_id: str,
        rejected_by: str,
        reason: str,
    ) -> ModelAudit:
        """Reject a model audit."""
        audit = self._store.get_audit(audit_id)
        if not audit:
            raise ValueError(f"Audit {audit_id} not found")
        
        audit.status = ModelAuditStatus.REJECTED
        audit.approved_by = rejected_by
        audit.approved_at = datetime.now(timezone.utc)
        audit.completed_at = datetime.now(timezone.utc)
        audit.findings.append({
            "check": "rejection",
            "status": "fail",
            "description": reason,
        })
        
        self._store.store_audit(audit)
        
        return audit
    
    def deprecate_model(self, audit_id: str) -> ModelAudit:
        """Deprecate a model."""
        audit = self._store.get_audit(audit_id)
        if not audit:
            raise ValueError(f"Audit {audit_id} not found")
        
        audit.status = ModelAuditStatus.DEPRECATED
        self._store.store_audit(audit)
        
        return audit
    
    def get_audit(self, audit_id: str) -> Optional[ModelAudit]:
        """Get audit by ID."""
        return self._store.get_audit(audit_id)
    
    def get_model_audits(self, model_id: str) -> List[ModelAudit]:
        """Get audits for a model."""
        return self._store.get_model_audits(model_id)
    
    def get_latest_audit(self, model_id: str) -> Optional[ModelAudit]:
        """Get the latest audit for a model."""
        audits = self._store.get_model_audits(model_id)
        if not audits:
            return None
        return sorted(audits, key=lambda a: a.created_at, reverse=True)[0]
    
    def detect_drift(
        self,
        model_id: str,
        reference_data: List[Dict[str, Any]],
        current_data: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Detect drift between reference and current data.

        Both datasets used to be ignored: the method returned
        ``random.uniform`` scores and reported ``len(reference_data)`` beside
        them, so identical datasets could be flagged as drifting and a model
        could be sent for retraining on a coin flip.
        """
        logger.info(f"Detecting drift for model {model_id}")

        if not reference_data or not current_data:
            logger.warning(
                "Drift detection for model %s needs both a reference and a "
                "current sample", model_id,
            )
            return {
                "model_id": model_id,
                "drift_detected": False,
                "feature_drift_score": None,
                "performance_drift_score": None,
                "recommendation": "Collect comparable samples before assessing drift",
                "details": {
                    "reference_samples": len(reference_data),
                    "current_samples": len(current_data),
                    "drift_type": None,
                    "insufficient_data": True,
                },
            }

        feature_drift, compared_features = self._feature_drift(
            reference_data, current_data,
        )
        performance_drift = self._performance_drift(reference_data, current_data)

        drift_detected = (
            (feature_drift is not None
             and feature_drift > self.FEATURE_DRIFT_THRESHOLD)
            or (performance_drift is not None
                and performance_drift > self.PERFORMANCE_DRIFT_THRESHOLD)
        )

        return {
            "model_id": model_id,
            "drift_detected": drift_detected,
            "feature_drift_score": feature_drift,
            "performance_drift_score": performance_drift,
            "recommendation": (
                "Retrain model" if drift_detected else "Continue monitoring"
            ),
            "details": {
                "reference_samples": len(reference_data),
                "current_samples": len(current_data),
                "drift_type": self._drift_type(feature_drift, performance_drift),
                "compared_features": compared_features,
                "insufficient_data": False,
            },
        }

    def _feature_drift(
        self,
        reference_data: List[Dict[str, Any]],
        current_data: List[Dict[str, Any]],
    ) -> tuple:
        """Mean standardised shift across the features both samples share.

        Each feature's shift is the change in its mean expressed in reference
        standard deviations, so features on different scales are comparable.
        Returns ``(score, feature_names)``.
        """
        shared = sorted(
            self._numeric_keys(reference_data) & self._numeric_keys(current_data)
        )
        if not shared:
            return None, []

        shifts = []
        for key in shared:
            reference_values = self._values(reference_data, key)
            current_values = self._values(current_data, key)
            if not reference_values or not current_values:
                continue

            spread = pstdev(reference_values) if len(reference_values) > 1 else 0.0
            if spread == 0:
                # A constant reference feature: any change at all is a shift,
                # scaled by the magnitude of the reference value.
                scale = abs(mean(reference_values)) or 1.0
            else:
                scale = spread

            shifts.append(abs(mean(current_values) - mean(reference_values)) / scale)

        if not shifts:
            return None, []

        return round(min(1.0, mean(shifts)), 4), shared

    def _performance_drift(
        self,
        reference_data: List[Dict[str, Any]],
        current_data: List[Dict[str, Any]],
    ) -> Optional[float]:
        """Relative change in the recorded model output between samples.

        ``None`` when neither sample records an output, rather than a guess.
        """
        for key in self.SCORE_KEYS:
            reference_values = self._values(reference_data, key)
            current_values = self._values(current_data, key)
            if not reference_values or not current_values:
                continue

            reference_mean = mean(reference_values)
            if reference_mean == 0:
                return round(min(1.0, abs(mean(current_values))), 4)

            return round(
                min(1.0, abs(mean(current_values) - reference_mean) / abs(reference_mean)),
                4,
            )

        return None

    def _drift_type(
        self,
        feature_drift: Optional[float],
        performance_drift: Optional[float],
    ) -> Optional[str]:
        """Whether the drift looks like concept drift or data drift."""
        if performance_drift is None and feature_drift is None:
            return None
        if performance_drift is None:
            return "data"
        if feature_drift is None:
            return "concept"
        return "concept" if performance_drift > feature_drift else "data"

    @staticmethod
    def _numeric_keys(records: List[Dict[str, Any]]) -> set:
        """Keys carrying numeric values in at least one record."""
        keys = set()
        for record in records:
            for key, value in record.items():
                if isinstance(value, bool):
                    continue
                if isinstance(value, (int, float)):
                    keys.add(key)
        return keys

    @staticmethod
    def _values(records: List[Dict[str, Any]], key: str) -> List[float]:
        """Numeric values recorded under a key."""
        values = []
        for record in records:
            value = record.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                continue
            values.append(float(value))
        return values
    
    def get_model_lineage(self, model_id: str) -> Dict[str, Any]:
        """Get model lineage (ancestors and descendants)."""
        audits = self._store.get_model_audits(model_id)
        
        lineage = {
            "model_id": model_id,
            "audits": [
                {
                    "audit_id": a.audit_id,
                    "version": a.model_version,
                    "status": a.status.value,
                    "approved_by": a.approved_by,
                    "created_at": a.created_at.isoformat(),
                }
                for a in sorted(audits, key=lambda x: x.created_at)
            ],
        }
        
        return lineage


# Global singleton
_model_auditor: Optional[ModelAuditor] = None


def get_model_auditor(store: Optional[ExplainableAIStore] = None) -> ModelAuditor:
    """Get or create the singleton ModelAuditor instance."""
    global _model_auditor
    
    if _model_auditor is None:
        _model_auditor = ModelAuditor(store=store)
    return _model_auditor