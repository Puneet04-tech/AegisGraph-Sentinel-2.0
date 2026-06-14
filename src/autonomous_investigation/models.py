"""
Core data models for Autonomous Fraud Investigation & Decision Intelligence Platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class InvestigationStatus(str, Enum):
    """Status of an investigation."""
    CREATED = "created"
    IN_PROGRESS = "in_progress"
    EVIDENCE_COLLECTED = "evidence_collected"
    ANALYZING = "analyzing"
    DECISION_PENDING = "decision_pending"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    CLOSED = "closed"
    ESCALATED = "escalated"


class EvidenceType(str, Enum):
    """Types of evidence."""
    TRANSACTION = "transaction"
    ACCOUNT = "account"
    DEVICE = "device"
    IP_ADDRESS = "ip_address"
    BEHAVIOR = "behavior"
    LOCATION = "location"
    IDENTITY = "identity"
    DOCUMENT = "document"
    COMMUNICATION = "communication"
    THREAT_INTEL = "threat_intelligence"
    ALERT = "alert"
    TIMELINE = "timeline"


class RiskLevel(str, Enum):
    """Risk level classification."""
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionType(str, Enum):
    """Types of investigation decisions."""
    APPROVE = "approve"
    REJECT = "reject"
    ESCALATE = "escalate"
    REVIEW = "review"
    CLOSE = "close"
    BLOCK = "block"
    FLAG = "flag"
    UNLOCK = "unlock"


class CasePriority(str, Enum):
    """Case priority levels."""
    P0_CRITICAL = "p0_critical"
    P1_HIGH = "p1_high"
    P2_MEDIUM = "p2_medium"
    P3_LOW = "p3_low"
    P4_ROUTINE = "p4_routine"


class SeverityLevel(str, Enum):
    """Severity level for findings."""
    INFO = "info"
    WARNING = "warning"
    MODERATE = "moderate"
    SEVERE = "severe"
    CRITICAL = "critical"


@dataclass
class InvestigationCase:
    """Autonomous investigation case."""
    case_id: str
    title: str
    description: str
    status: InvestigationStatus
    priority: CasePriority
    severity: SeverityLevel
    alert_ids: List[str] = field(default_factory=list)
    entity_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    assigned_analyst: Optional[str] = None
    risk_score: float = 0.0
    confidence_score: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    sla_deadline: Optional[datetime] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    patterns_detected: List[str] = field(default_factory=list)
    correlations_found: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceArtifact:
    """Evidence collected during investigation."""
    evidence_id: str
    evidence_type: EvidenceType
    source_system: str
    source_id: str
    content: Dict[str, Any]
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    relevance_score: float = 1.0
    confidence: float = 1.0
    is_verified: bool = False
    verified_by: Optional[str] = None
    verified_at: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskAssessment:
    """Risk assessment for investigation."""
    assessment_id: str
    case_id: str
    risk_level: RiskLevel
    risk_score: float
    risk_factors: List[str]
    risk_categories: Dict[str, float]
    mitigation_factors: List[str]
    residual_risk: float
    assessment_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 1.0
    model_version: str = "1.0"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DecisionRecommendation:
    """AI-generated decision recommendation."""
    recommendation_id: str
    case_id: str
    decision_type: DecisionType
    confidence: float
    supporting_evidence: List[str]
    risk_explanation: str
    recommended_actions: List[str]
    alternative_decisions: List[Dict[str, Any]] = field(default_factory=list)
    decision_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    model_id: str = "decision-intelligence-v1"
    model_confidence: float = 1.0
    requires_human_review: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FraudNarrative:
    """AI-generated fraud narrative."""
    narrative_id: str
    case_id: str
    summary: str
    detailed_narrative: str
    key_findings: List[str]
    timeline_description: str
    fraud_indicators: List[str]
    affected_entities: List[str]
    financial_impact: Optional[float] = None
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    narrative_type: str = "full"
    confidence_score: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InvestigationTimeline:
    """Timeline of investigation events."""
    timeline_id: str
    case_id: str
    events: List[Dict[str, Any]]
    reconstructed_sequence: List[str]
    critical_path: List[str]
    anomalies_detected: List[str]
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalystRecommendation:
    """Recommendation for analyst action."""
    recommendation_id: str
    case_id: str
    recommendation_type: str
    description: str
    priority: CasePriority
    suggested_actions: List[str]
    questions_to_answer: List[str] = field(default_factory=list)
    related_evidence: List[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_read: bool = False
    is_acknowledged: bool = False


@dataclass
class EntityCorrelation:
    """Entity correlation discovered during investigation."""
    correlation_id: str
    case_id: str
    entity_1_id: str
    entity_2_id: str
    correlation_type: str
    strength: float
    shared_attributes: List[str]
    discovery_method: str
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    verified: bool = False


@dataclass
class FraudPattern:
    """Detected fraud pattern."""
    pattern_id: str
    pattern_type: str
    pattern_name: str
    description: str
    indicators: List[str]
    severity: SeverityLevel
    frequency: int
    first_seen: datetime
    last_seen: datetime
    affected_cases: List[str]
    confidence_score: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ActionPlan:
    """Action plan for case resolution."""
    action_id: str
    case_id: str
    actions: List[Dict[str, Any]]
    recommended_sequence: List[str]
    estimated_duration_minutes: int
    required_roles: List[str]
    priority: CasePriority
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "pending"


@dataclass
class CaseMetrics:
    """Metrics for investigation case."""
    case_id: str
    time_to_analyze_minutes: float
    evidence_collected: int
    patterns_found: int
    correlations_found: int
    false_positive_likelihood: float
    investigator_efficiency_score: float
    calculated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AuditRecord:
    """Audit record for investigation operations."""
    record_id: str
    operation: str
    case_id: Optional[str]
    user_id: str
    action: str
    details: Dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ip_address: str = "unknown"
    success: bool = True
    error_message: Optional[str] = None