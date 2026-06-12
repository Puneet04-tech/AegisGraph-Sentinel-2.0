"""
Financial Crime Intelligence Exchange Models.

Models for global financial crime intelligence platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class InstitutionType(str, Enum):
    """Institution types."""
    BANK = "bank"
    INSURANCE = "insurance"
    INVESTMENT = "investment"
    PAYMENT = "payment"
    REGULATOR = "regulator"
    EXCHANGE = "exchange"


class ShareLevel(str, Enum):
    """Intelligence sharing levels."""
    FULL = "full"
    ANONYMIZED = "anonymized"
    RESTRICTED = "restricted"


class CaseStatus(str, Enum):
    """Case status."""
    OPEN = "open"
    INVESTIGATING = "investigating"
    SHARED = "shared"
    CLOSED = "closed"


class AlertLevel(str, Enum):
    """Alert levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Institution:
    """Partner institution."""
    institution_id: str
    name: str
    institution_type: InstitutionType
    country: str
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    trust_score: float = 1.0
    intelligence_shared: int = 0
    intelligence_received: int = 0


@dataclass
class FraudAlert:
    """Fraud alert for sharing."""
    alert_id: str
    source_institution: str
    alert_type: str
    account_identifier: str
    amount: float
    description: str
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    share_level: ShareLevel = ShareLevel.ANONYMIZED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class FraudPattern:
    """Identified fraud pattern."""
    pattern_id: str
    pattern_type: str
    description: str
    indicators: List[str] = field(default_factory=list)
    affected_institutions: List[str] = field(default_factory=list)
    confidence: float = 0.5
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SharedCase:
    """Shared investigation case."""
    case_id: str
    source_institution: str
    title: str
    description: str
    case_type: str
    status: CaseStatus = CaseStatus.OPEN
    participants: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AMLIntelligence:
    """AML intelligence record."""
    intel_id: str
    source_institution: str
    subject_type: str
    subject_identifier: str
    risk_indicators: List[str] = field(default_factory=list)
    sar_filed: bool = False
    compliance_notes: str = ""
    share_level: ShareLevel = ShareLevel.ANONYMIZED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CrossBorderInvestigation:
    """Cross-border investigation."""
    investigation_id: str
    title: str
    primary_institution: str
    involved_institutions: List[str] = field(default_factory=list)
    subjects: List[str] = field(default_factory=list)
    status: str = "pending"
    findings: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AuditEvent:
    """Audit event."""
    event_id: str
    timestamp: datetime
    user_id: str
    action: str
    resource_type: str
    resource_id: str
    details: Dict[str, Any] = field(default_factory=dict)
    success: bool = True