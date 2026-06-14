"""
Digital Risk Protection Models.

Models for digital risk protection platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class RiskLevel(str, Enum):
    """Risk severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatType(str, Enum):
    """Digital threat types."""
    PHISHING = "phishing"
    BRAND_IMPERSONATION = "brand_impersonation"
    FAKE_DOMAIN = "fake_domain"
    DATA_BREACH = "data_breach"
    DARK_WEB_EXPOSURE = "dark_web_exposure"
    SOCIAL_MEDIA_ABUSE = "social_media_abuse"
    FRAUD_INFRASTRUCTURE = "fraud_infrastructure"


class ThreatStatus(str, Enum):
    """Threat status."""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    TAKEDOWN_REQUESTED = "takedown_requested"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Domain:
    """Monitored domain."""
    domain_id: str
    domain: str
    registrar: Optional[str] = None
    registration_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    nameservers: List[str] = field(default_factory=list)
    ssl_info: Optional[Dict[str, Any]] = None


@dataclass
class PhishingAlert:
    """Phishing detection alert."""
    alert_id: str
    target_domain: str
    phishing_url: str
    target_brand: Optional[str] = None
    landing_page_hash: Optional[str] = None
    screenshots: List[str] = field(default_factory=list)
    status: ThreatStatus = ThreatStatus.NEW
    confidence: float = 0.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class BrandImpersonation:
    """Brand impersonation detection."""
    impersonation_id: str
    brand_name: str
    impersonating_domain: str
    type: str
    status: ThreatStatus = ThreatStatus.NEW
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CredentialExposure:
    """Credential exposure record."""
    exposure_id: str
    email: str
    source: str
    breach_date: Optional[datetime] = None
    password_hash: Optional[str] = None
    exposure_type: str = "credential_dump"
    affected_employees: int = 0
    status: str = "new"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DarkWebIntelligence:
    """Dark web intelligence record."""
    intel_id: str
    source: str
    content_type: str
    title: str
    description: str
    indicators: List[str] = field(default_factory=list)
    confidence: float = 0.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SocialMediaAbuse:
    """Social media abuse record."""
    abuse_id: str
    platform: str
    account_handle: str
    content: str
    type: str
    status: ThreatStatus = ThreatStatus.NEW
    sentiment_score: float = 0.0
    engagement: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ExternalAttackSurface:
    """External attack surface record."""
    surface_id: str
    asset_type: str
    asset_value: str
    exposure_level: str
    vulnerabilities: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class RiskScore:
    """Overall digital risk score."""
    score_id: str
    organization_id: str
    overall_score: float
    phishing_score: float = 0.0
    brand_risk_score: float = 0.0
    credential_risk_score: float = 0.0
    dark_web_risk_score: float = 0.0
    social_media_risk_score: float = 0.0
    attack_surface_score: float = 0.0
    calculated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Alert:
    """DRP alert."""
    alert_id: str
    alert_type: ThreatType
    title: str
    description: str
    severity: RiskLevel
    status: ThreatStatus = ThreatStatus.NEW
    related_threats: List[str] = field(default_factory=list)
    assigned_to: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AuditEvent:
    """Audit event for DRP operations."""
    event_id: str
    timestamp: datetime
    user_id: str
    action: str
    resource_type: str
    resource_id: str
    details: Dict[str, Any] = field(default_factory=dict)
    success: bool = True