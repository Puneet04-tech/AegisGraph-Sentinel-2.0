"""
Explainable AI & Compliance Engine Models.

Data models for AI explanations, decision traces, and compliance reports.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid


class ExplanationType(str, Enum):
    """Explanation types."""
    SHAP = "SHAP"
    LIME = "LIME"
    FEATURE_IMPORTANCE = "FEATURE_IMPORTANCE"
    COUNTERFACTUAL = "COUNTERFACTUAL"


class ComplianceFramework(str, Enum):
    """Compliance frameworks."""
    GDPR = "GDPR"
    CCPA = "CCPA"
    ECOA = "ECOA"
    FAIR_LENDING = "FAIR_LENDING"
    SR_11_7 = "SR_11_7"


class BiasMetric(str, Enum):
    """Bias metrics."""
    DISPARATE_IMPACT = "DISPARATE_IMPACT"
    EQUALIZED_ODDS = "EQUALIZED_ODDS"
    CALIBRATION = "CALIBRATION"
    INDIVIDUAL_FAIRNESS = "INDIVIDUAL_FAIRNESS"


class ModelAuditStatus(str, Enum):
    """Model audit status."""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    DEPRECATED = "DEPRECATED"


class FeatureImportance(BaseModel):
    """Feature importance record."""
    feature: str
    importance: float
    direction: str = "positive"  # positive, negative, neutral
    confidence: float = 1.0


class Explanation(BaseModel):
    """AI decision explanation."""
    explanation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    decision_id: str
    explanation_type: ExplanationType
    model_id: str
    model_version: str
    features: List[FeatureImportance] = Field(default_factory=list)
    base_value: float = 0.0
    prediction_value: float = 0.0
    confidence: float = 1.0
    summary: str
    top_contributing_features: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DecisionTrace(BaseModel):
    """Decision trace record."""
    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    decision_id: str
    model_id: str
    model_version: str
    model_name: str
    input_features: Dict[str, Any] = Field(default_factory=dict)
    output_decision: str
    output_score: float
    decision_factors: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: Optional[str] = None
    case_id: Optional[str] = None
    transaction_id: Optional[str] = None
    processing_time_ms: float = 0.0


class ComplianceReport(BaseModel):
    """Compliance report."""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    report_type: str  # fair_lending, adverse_action, regulatory
    framework: ComplianceFramework
    period_start: datetime
    period_end: datetime
    summary: str
    metrics: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "system"


class BiasAnalysis(BaseModel):
    """Bias analysis result."""
    analysis_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_id: str
    protected_attribute: str
    metric: BiasMetric
    value: float
    threshold: float = 0.8  # 80% rule
    compliant: bool
    affected_groups: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ModelAudit(BaseModel):
    """Model audit record."""
    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_id: str
    model_name: str
    model_version: str
    status: ModelAuditStatus = ModelAuditStatus.PENDING
    audit_type: str  # initial, periodic, triggered
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    training_data_hash: Optional[str] = None
    feature_drift_score: Optional[float] = None
    performance_drift_score: Optional[float] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None


class CounterfactualExplanation(BaseModel):
    """Counterfactual explanation."""
    cf_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    decision_id: str
    original_instance: Dict[str, Any]
    counterfactual_instance: Dict[str, Any]
    changed_features: List[str] = Field(default_factory=list)
    feature_changes: Dict[str, Any] = Field(default_factory=dict)
    outcome_change: str  # fraud to non-fraud or vice versa
    proximity_score: float = 0.0
    sparsity_score: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AdverseActionNotice(BaseModel):
    """Adverse action notice."""
    notice_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    decision_id: str
    reason_codes: List[str] = Field(default_factory=list)
    reasons_description: str
    specific_reasons: List[str] = Field(default_factory=list)
    custom_reason: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sent_at: Optional[datetime] = None
    recipient: str