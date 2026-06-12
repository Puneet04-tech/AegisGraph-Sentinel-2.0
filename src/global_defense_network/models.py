"""
Global AI Fraud Defense Network Models.

Distributed fraud defense ecosystem models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class TrustLevel(str, Enum):
    """Trust levels for federation."""
    VERIFIED = "verified"
    TRUSTED = "trusted"
    PROVISIONAL = "provisional"
    RESTRICTED = "restricted"


class ThreatCampaignStatus(str, Enum):
    """Status of threat campaigns."""
    ACTIVE = "active"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    CLOSED = "closed"


class IntelligenceSharingLevel(str, Enum):
    """Sharing level for intelligence."""
    FULL = "full"
    ANONYMIZED = "anonymized"
    SUMMARY = "summary"
    MINIMAL = "minimal"


@dataclass
class Institution:
    """Member institution in the defense network."""
    institution_id: str
    name: str
    trust_level: TrustLevel = TrustLevel.PROVISIONAL
    reputation_score: float = 0.5
    last_sync: Optional[datetime] = None
    capabilities: List[str] = field(default_factory=list)
    regions: List[str] = field(default_factory=list)


@dataclass
class ThreatIntelligence:
    """Shared threat intelligence."""
    intelligence_id: str
    source_institution: str
    threat_type: str
    indicators: List[Dict[str, Any]]
    confidence: float
    sharing_level: IntelligenceSharingLevel = IntelligenceSharingLevel.ANONYMIZED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class FraudCampaign:
    """Identified fraud campaign."""
    campaign_id: str
    name: str
    status: ThreatCampaignStatus = ThreatCampaignStatus.ACTIVE
    threat_level: float = 0.5
    affected_institutions: List[str] = field(default_factory=list)
    attributed_actors: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    first_detected: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    financial_impact: Optional[float] = None
    prevention_amount: float = 0.0


@dataclass
class ThreatForecast:
    """Threat forecast prediction."""
    forecast_id: str
    predicted_threat_type: str
    probability: float
    confidence: float
    predicted_impact: float
    affected_regions: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    forecast_period: str = "7d"
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DefenseResponse:
    """AI-generated defense response."""
    response_id: str
    campaign_id: Optional[str]
    response_type: str
    recommended_actions: List[Dict[str, Any]]
    confidence: float
    coordination_required: bool = False
    participating_institutions: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CrossCorrelation:
    """Cross-institution correlation result."""
    correlation_id: str
    institution_1: str
    institution_2: str
    correlation_type: str
    confidence: float
    threat_level: float
    shared_indicators: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class NetworkMetrics:
    """Global defense network metrics."""
    total_institutions: int
    active_threats: int
    campaigns_tracked: int
    intelligence_shared: int
    threats_forecasted: int
    response_coordination: int
    avg_trust_score: float


@dataclass
class DefenseConfig:
    """Configuration for global defense network."""
    federation_enabled: bool = True
    auto_share_threshold: float = 0.7
    trust_renewal_days: int = 90
    intelligence_ttl_hours: int = 168
    forecast_window_days: int = 7
    min_correlation_confidence: float = 0.6
    anonymization_level: IntelligenceSharingLevel = IntelligenceSharingLevel.ANONYMIZED