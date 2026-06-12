"""
Core data models for Autonomous Fraud Prevention & Adaptive Risk Control Platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class RiskLevel(str, Enum):
    """Risk level classification."""
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionType(str, Enum):
    """Types of risk decisions."""
    APPROVE = "approve"
    DENY = "deny"
    BLOCK = "block"
    CHALLENGE = "challenge"
    REVIEW = "review"
    MONITOR = "monitor"
    ESCALATE = "escalate"


class ControlStatus(str, Enum):
    """Status of control rules."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    TESTING = "testing"
    DEPRECATED = "deprecated"


class MitigationAction(str, Enum):
    """Mitigation actions for threats."""
    BLOCK = "block"
    CHALLENGE = "challenge"
    LIMIT = "limit"
    FLAG = "flag"
    NOTIFY = "notify"
    ESCALATE = "escalate"
    ISOLATE = "isolate"
    FREEZE = "freeze"


class LearningFeedbackType(str, Enum):
    """Types of learning feedback."""
    POSITIVE = "positive"
    NEGATIVE = "negative"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    ADJUSTMENT = "adjustment"


@dataclass
class RiskProfile:
    """User or entity risk profile."""
    profile_id: str
    entity_id: str
    entity_type: str
    risk_score: float
    risk_level: RiskLevel
    trust_score: float
    last_evaluation: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    risk_factors: List[str] = field(default_factory=list)
    mitigation_applied: List[str] = field(default_factory=list)
    total_transactions: int = 0
    fraudulent_transactions: int = 0
    risk_trend: str = "stable"
    behavioral_baseline: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskDecision:
    """Risk decision for a transaction or action."""
    decision_id: str
    entity_id: str
    transaction_id: Optional[str]
    decision_type: DecisionType
    risk_level: RiskLevel
    risk_score: float
    confidence: float
    factors: List[str]
    recommended_actions: List[str]
    controls_applied: List[str] = field(default_factory=list)
    decision_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    requires_review: bool = False
    reviewer_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FraudAttempt:
    """Detected fraud attempt."""
    attempt_id: str
    entity_id: str
    attempt_type: str
    risk_score: float
    confidence: float
    indicators: List[str]
    affected_transactions: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    prevented: bool = False
    prevention_method: Optional[str] = None
    damage_estimated: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AdaptivePolicy:
    """Adaptive security policy."""
    policy_id: str
    name: str
    description: str
    risk_threshold: float
    control_actions: List[MitigationAction]
    conditions: Dict[str, Any]
    is_active: bool = True
    priority: int = 100
    version: str = "1.0"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0
    success_rate: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ControlRule:
    """Security control rule."""
    rule_id: str
    name: str
    rule_type: str
    conditions: Dict[str, Any]
    action: MitigationAction
    risk_threshold: float
    is_active: bool = True
    priority: int = 100
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0
    false_positive_rate: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TransactionAssessment:
    """Real-time transaction risk assessment."""
    assessment_id: str
    transaction_id: str
    entity_id: str
    risk_score: float
    risk_level: RiskLevel
    decision: DecisionType
    confidence: float
    risk_factors: List[str]
    indicators: List[str]
    velocity_score: float = 0.0
    behavioral_score: float = 0.0
    device_score: float = 0.0
    location_score: float = 0.0
    amount_score: float = 0.0
    assessed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    processing_time_ms: float = 0.0
    controls_triggered: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskRecommendation:
    """AI-generated risk recommendation."""
    recommendation_id: str
    entity_id: str
    recommendation_type: str
    description: str
    priority: int
    actions: List[str]
    expected_impact: float
    risk_reduction: float
    implementation_difficulty: str = "medium"
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_implemented: bool = False
    implemented_at: Optional[datetime] = None


@dataclass
class LearningFeedback:
    """Feedback for adaptive learning."""
    feedback_id: str
    entity_id: str
    transaction_id: Optional[str]
    feedback_type: LearningFeedbackType
    risk_score_predicted: float
    risk_score_actual: float
    features: Dict[str, float]
    model_version: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_processed: bool = False


@dataclass
class AuditRecord:
    """Audit record for risk operations."""
    record_id: str
    operation: str
    entity_id: Optional[str]
    transaction_id: Optional[str]
    user_id: str
    action: str
    details: Dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ip_address: str = "unknown"
    success: bool = True
    error_message: Optional[str] = None


@dataclass
class PolicyChange:
    """Record of policy changes."""
    change_id: str
    policy_id: str
    change_type: str
    old_value: Dict[str, Any]
    new_value: Dict[str, Any]
    reason: str
    changed_by: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    approved_by: Optional[str] = None


@dataclass
class ThreatIndicator:
    """Threat indicator for monitoring."""
    indicator_id: str
    indicator_type: str
    indicator_value: str
    threat_category: str
    severity: RiskLevel
    confidence: float
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    occurrence_count: int = 0
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)