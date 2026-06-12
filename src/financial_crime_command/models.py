"""
Financial Crime Command Center Models.

Centralized models for the Autonomous Financial Crime Command Center.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class CrimeType(str, Enum):
    """Types of financial crime."""
    FRAUD = "fraud"
    AML = "aml"
    INSIDER_THREAT = "insider_threat"
    CYBERCRIME = "cybercrime"
    MONEY_LAUNDERING = "money_laundering"
    TERRORIST_FINANCING = "terrorist_financing"
    SANCTIONS_EVASION = "sanctions_evasion"
    MARKET_MANIPULATION = "market_manipulation"


class CaseStatus(str, Enum):
    """Status of financial crime cases."""
    CREATED = "created"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    UNDER_REVIEW = "under_review"
    ESCALATED = "escalated"
    CLOSED = "closed"
    DISMISSED = "dismissed"


class ThreatLevel(str, Enum):
    """Threat level classification."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    SEVERE = "severe"


class AlertStatus(str, Enum):
    """Status of financial crime alerts."""
    TRIGGERED = "triggered"
    REVIEWED = "reviewed"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ESCALATED = "escalated"


@dataclass
class CrimeCase:
    """Financial crime case model."""
    case_id: str
    title: str
    description: str
    crime_type: CrimeType
    status: CaseStatus = CaseStatus.CREATED
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    priority_score: float = 0.5
    entity_ids: List[str] = field(default_factory=list)
    linked_cases: List[str] = field(default_factory=list)
    assigned_to: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    risk_indicators: List[str] = field(default_factory=list)
    financial_impact: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatIndicator:
    """Threat indicator for fusion engine."""
    indicator_id: str
    indicator_type: str
    value: Any
    confidence: float
    source: str
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: List[str] = field(default_factory=list)


@dataclass
class Alert:
    """Financial crime alert."""
    alert_id: str
    title: str
    description: str
    crime_type: CrimeType
    threat_level: ThreatLevel
    status: AlertStatus = AlertStatus.TRIGGERED
    entity_ids: List[str] = field(default_factory=list)
    case_id: Optional[str] = None
    confidence_score: float = 0.5
    triggered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    risk_indicators: List[str] = field(default_factory=list)


@dataclass
class CorrelationLink:
    """Link between correlated cases."""
    link_id: str
    source_case_id: str
    target_case_id: str
    correlation_type: str
    confidence: float
    shared_entities: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DashboardMetrics:
    """Command center dashboard metrics."""
    total_cases: int
    open_cases: int
    closed_cases: int
    escalated_cases: int
    high_priority_cases: int
    avg_resolution_time: float
    cases_by_type: Dict[str, int]
    cases_by_status: Dict[str, int]
    threat_level_distribution: Dict[str, int]
    recent_alerts: int
    pending_investigations: int


@dataclass
class AnalyticsReport:
    """Analytics report for command center."""
    report_id: str
    period_start: datetime
    period_end: datetime
    total_alerts: int
    confirmed_fraud: int
    false_positives: int
    financial_impact_prevented: float
    case_closure_rate: float
    avg_investigation_time: float
    top_crime_types: List[Dict[str, Any]]
    trends: Dict[str, Any]
    recommendations: List[str]


@dataclass
class AuditEntry:
    """Audit entry for command center operations."""
    entry_id: str
    timestamp: datetime
    user_id: str
    action: str
    resource_type: str
    resource_id: str
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    severity: str = "info"


@dataclass
class CommandCenterConfig:
    """Configuration for command center."""
    max_concurrent_investigations: int = 100
    alert_threshold_high: float = 0.8
    alert_threshold_medium: float = 0.5
    auto_escalate_threshold: float = 0.9
    correlation_window_hours: int = 24
    retention_days: int = 365
    enable_auto_assessment: bool = True
    enable_predictive_prioritization: bool = True