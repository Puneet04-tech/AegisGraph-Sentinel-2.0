"""
Data Models for Campaign Attribution Platform
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ActorType(str, Enum):
    """Types of threat actors."""
    NATION_STATE = "nation_state"
    ORGANIZED_CRIME = "organized_crime"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    OPPORTUNIST = "opportunist"
    UNKNOWN = "unknown"


class CampaignStatus(str, Enum):
    """Campaign status."""
    ACTIVE = "active"
    DORMANT = "dormant"
    DISRUPTED = "disrupted"
    ATTRIBUTED = "attributed"
    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    """Confidence levels for attributions."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class InfrastructureType(str, Enum):
    """Types of infrastructure."""
    COMMAND_CONTROL = "command_control"
    PHISHING = "phishing"
    DATA_EXFILTRATION = "data_exfiltration"
    FRAUD = "fraud"
    MULE = "mule"
    DROP = "drop"
    UNKNOWN = "unknown"


class InfrastructureStatus(str, Enum):
    """Infrastructure status."""
    ACTIVE = "active"
    PARKING = "parking"
    TAKEDOWN = "takedown"
    UNKNOWN = "unknown"


@dataclass
class Infrastructure:
    """Infrastructure used by threat actors."""
    infrastructure_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ip_addresses: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    asn: Optional[str] = None
    hosting_provider: Optional[str] = None
    infrastructure_type: InfrastructureType = InfrastructureType.UNKNOWN
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: InfrastructureStatus = InfrastructureStatus.ACTIVE
    linked_campaigns: List[str] = field(default_factory=list)
    linked_actors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "infrastructure_id": self.infrastructure_id,
            "ip_addresses": self.ip_addresses,
            "domains": self.domains,
            "asn": self.asn,
            "hosting_provider": self.hosting_provider,
            "infrastructure_type": self.infrastructure_type.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "status": self.status.value,
            "linked_campaigns": self.linked_campaigns,
            "linked_actors": self.linked_actors,
            "metadata": self.metadata,
        }


@dataclass
class AttackPattern:
    """Attack pattern used in campaigns."""
    pattern_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: str = ""
    techniques: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    linked_campaigns: List[str] = field(default_factory=list)
    first_observed: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "name": self.name,
            "category": self.category,
            "techniques": self.techniques,
            "indicators": self.indicators,
            "linked_campaigns": self.linked_campaigns,
            "first_observed": self.first_observed,
            "metadata": self.metadata,
        }


@dataclass
class ThreatActor:
    """Threat actor profile."""
    actor_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    alias: List[str] = field(default_factory=list)
    actor_type: ActorType = ActorType.UNKNOWN
    description: str = ""
    motivation: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    linked_campaigns: List[str] = field(default_factory=list)
    linked_infrastructure: List[str] = field(default_factory=list)
    associated_actors: List[str] = field(default_factory=list)
    active_since: Optional[str] = None
    last_activity: Optional[str] = None
    attribution_confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    is_active: bool = True
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "name": self.name,
            "alias": self.alias,
            "actor_type": self.actor_type.value,
            "description": self.description,
            "motivation": self.motivation,
            "capabilities": self.capabilities,
            "linked_campaigns": self.linked_campaigns,
            "linked_infrastructure": self.linked_infrastructure,
            "associated_actors": self.associated_actors,
            "active_since": self.active_since,
            "last_activity": self.last_activity,
            "attribution_confidence": self.attribution_confidence.value,
            "is_active": self.is_active,
            "tags": self.tags,
            "metadata": self.metadata,
        }


@dataclass
class Campaign:
    """Fraud campaign."""
    campaign_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    status: CampaignStatus = CampaignStatus.UNKNOWN
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    target_sectors: List[str] = field(default_factory=list)
    target_geographies: List[str] = field(default_factory=list)
    victim_count: int = 0
    estimated_damage: float = 0.0
    linked_indicators: List[str] = field(default_factory=list)
    linked_infrastructure: List[str] = field(default_factory=list)
    linked_patterns: List[str] = field(default_factory=list)
    attributed_actors: List[str] = field(default_factory=list)
    attribution_confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    attack_vectors: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "target_sectors": self.target_sectors,
            "target_geographies": self.target_geographies,
            "victim_count": self.victim_count,
            "estimated_damage": self.estimated_damage,
            "linked_indicators": self.linked_indicators,
            "linked_infrastructure": self.linked_infrastructure,
            "linked_patterns": self.linked_patterns,
            "attributed_actors": self.attributed_actors,
            "attribution_confidence": self.attribution_confidence.value,
            "attack_vectors": self.attack_vectors,
            "tags": self.tags,
            "metadata": self.metadata,
        }


@dataclass
class Attribution:
    """Attribution record linking campaigns to actors."""
    attribution_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    campaign_id: str = ""
    actor_id: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    evidence: List[str] = field(default_factory=list)
    attribution_method: str = ""
    attributed_by: str = "system"
    attributed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_confirmed: bool = False
    notes: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attribution_id": self.attribution_id,
            "campaign_id": self.campaign_id,
            "actor_id": self.actor_id,
            "confidence": self.confidence.value,
            "evidence": self.evidence,
            "attribution_method": self.attribution_method,
            "attributed_by": self.attributed_by,
            "attributed_at": self.attributed_at,
            "is_confirmed": self.is_confirmed,
            "notes": self.notes,
            "metadata": self.metadata,
        }


@dataclass
class ThreatProfile:
    """Complete threat profile for an actor or campaign."""
    profile_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: str = ""  # "actor" or "campaign"
    entity_id: str = ""
    name: str = ""
    risk_score: float = 0.0
    threat_level: str = "medium"
    capabilities: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    infrastructure: List[str] = field(default_factory=list)
    associated_entities: List[str] = field(default_factory=list)
    activity_timeline: List[Dict[str, Any]] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "name": self.name,
            "risk_score": self.risk_score,
            "threat_level": self.threat_level,
            "capabilities": self.capabilities,
            "indicators": self.indicators,
            "infrastructure": self.infrastructure,
            "associated_entities": self.associated_entities,
            "activity_timeline": self.activity_timeline,
            "recommended_actions": self.recommended_actions,
            "metadata": self.metadata,
        }


@dataclass
class RiskAssessment:
    """Risk assessment for campaigns or actors."""
    assessment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: str = ""
    entity_id: str = ""
    risk_score: float = 0.0
    threat_level: str = "medium"
    likelihood: float = 0.0
    impact: float = 0.0
    factors: Dict[str, float] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    assessed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "risk_score": self.risk_score,
            "threat_level": self.threat_level,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "factors": self.factors,
            "recommendations": self.recommendations,
            "assessed_at": self.assessed_at,
        }


@dataclass
class CampaignStats:
    """Statistics for campaigns."""
    total_campaigns: int = 0
    active_campaigns: int = 0
    attributed_campaigns: int = 0
    total_actors: int = 0
    active_actors: int = 0
    total_infrastructure: int = 0
    campaigns_by_status: Dict[str, int] = field(default_factory=dict)
    campaigns_by_type: Dict[str, int] = field(default_factory=dict)
    average_confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_campaigns": self.total_campaigns,
            "active_campaigns": self.active_campaigns,
            "attributed_campaigns": self.attributed_campaigns,
            "total_actors": self.total_actors,
            "active_actors": self.active_actors,
            "total_infrastructure": self.total_infrastructure,
            "campaigns_by_status": self.campaigns_by_status,
            "campaigns_by_type": self.campaigns_by_type,
            "average_confidence": self.average_confidence,
        }
