"""
Executive Risk Governance Platform Models.

Data models for executive dashboards, board reporting, compliance analytics,
risk governance, and audit intelligence.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid


class RiskLevel(str, Enum):
    """Risk levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


class ComplianceStatus(str, Enum):
    """Compliance status."""
    COMPLIANT = "COMPLIANT"
    PARTIAL = "PARTIAL"
    NON_COMPLIANT = "NON_COMPLIANT"
    PENDING = "PENDING"
    EXPIRED = "EXPIRED"


class AuditFindingSeverity(str, Enum):
    """Audit finding severity."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ReportType(str, Enum):
    """Report types."""
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"
    BOARD_REPORT = "BOARD_REPORT"
    COMPLIANCE_REPORT = "COMPLIANCE_REPORT"
    RISK_REPORT = "RISK_REPORT"
    AUDIT_REPORT = "AUDIT_REPORT"
    TREND_REPORT = "TREND_REPORT"


class GovernanceMetric(BaseModel):
    """Governance metric data."""
    metric_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    value: float
    unit: str
    category: str
    trend: str  # "increasing", "stable", "decreasing"
    change_percent: float
    benchmark: Optional[float] = None
    threshold: Optional[float] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RiskScorecard(BaseModel):
    """Enterprise risk scorecard."""
    scorecard_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    period: str
    overall_risk_score: float
    risk_level: RiskLevel
    risk_categories: Dict[str, float] = Field(default_factory=dict)
    risk_trend: str
    key_risks: List[Dict[str, Any]] = Field(default_factory=list)
    risk_indicators: Dict[str, Any] = Field(default_factory=dict)
    mitigation_actions: List[str] = Field(default_factory=list)
    owner: Optional[str] = None
    next_review_date: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ComplianceFramework(BaseModel):
    """Compliance framework tracking."""
    framework_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    framework_name: str
    version: str
    status: ComplianceStatus
    controls: List[Dict[str, Any]] = Field(default_factory=list)
    compliance_percentage: float
    last_audit_date: Optional[datetime] = None
    next_audit_date: Optional[datetime] = None
    findings_count: int
    open_findings: int
    critical_findings: int
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ControlAssessment(BaseModel):
    """Control assessment result."""
    assessment_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    control_id: str
    control_name: str
    framework: str
    status: ComplianceStatus
    effectiveness_score: float
    last_tested: Optional[datetime] = None
    next_test_date: Optional[datetime] = None
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    owner: Optional[str] = None


class AuditFinding(BaseModel):
    """Audit finding."""
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_title: str
    description: str
    severity: AuditFindingSeverity
    category: str
    affected_controls: List[str] = Field(default_factory=list)
    affected_entities: List[str] = Field(default_factory=list)
    risk_impact: float
    financial_impact: Optional[float] = None
    remediation_steps: List[str] = Field(default_factory=list)
    status: str = "OPEN"
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    closed_date: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BoardMetric(BaseModel):
    """Board-level metric."""
    metric_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: str
    metric_name: str
    current_value: float
    target_value: float
    variance: float
    trend: str
    period: str
    context: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExecutiveDashboard(BaseModel):
    """Executive dashboard data."""
    dashboard_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    period: str
    risk_summary: Dict[str, Any] = Field(default_factory=dict)
    compliance_summary: Dict[str, Any] = Field(default_factory=dict)
    performance_summary: Dict[str, Any] = Field(default_factory=dict)
    key_metrics: List[BoardMetric] = Field(default_factory=list)
    alerts: List[Dict[str, Any]] = Field(default_factory=list)
    trends: Dict[str, Any] = Field(default_factory=dict)
    generated_by: str = "EXECUTIVE_GOVERNANCE"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GovernanceReport(BaseModel):
    """Governance report."""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    report_type: ReportType
    title: str
    period_start: datetime
    period_end: datetime
    summary: Dict[str, Any] = Field(default_factory=dict)
    metrics: List[Any] = Field(default_factory=list)  # Allow dict or GovernanceMetric
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    attachments: List[str] = Field(default_factory=list)
    approved_by: Optional[str] = None
    status: str = "DRAFT"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PolicyViolation(BaseModel):
    """Policy violation record."""
    violation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    policy_id: str
    policy_name: str
    entity_id: str
    entity_type: str
    severity: AuditFindingSeverity
    description: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "OPEN"
    remediation: Optional[str] = None
    closed_at: Optional[datetime] = None


class RiskThreshold(BaseModel):
    """Risk threshold configuration."""
    threshold_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    metric_name: str
    warning_level: float
    critical_level: float
    action_required: str
    notification_list: List[str] = Field(default_factory=list)
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# Store singleton
_store = None


def get_governance_store():
    """Get or create the governance store singleton."""
    global _store
    if _store is None:
        from .store import GovernanceStore
        _store = GovernanceStore()
    return _store