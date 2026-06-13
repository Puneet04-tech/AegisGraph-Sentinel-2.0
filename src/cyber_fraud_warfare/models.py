"""
Data models for Cyber-Fraud Warfare Intelligence Platform.

Core models:
    ThreatActor: Threat actor profile
    Campaign: Attack campaign model
    Attribution: Campaign attribution data
    ThreatProfile: Entity threat profile
    AttackPattern: Known attack pattern
    RiskAssessment: Risk assessment result
    ThreatRelationship: Relationship between threats
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
import uuid


class ThreatActorType(str, Enum):
    """Types of threat actors."""
    NATION_STATE = "NATION_STATE"
    CYBERCRIME_ORG = "CYBERCRIME_ORG"
    HACKTIVIST = "HACKTIVIST"
    INSIDER = "INSIDER"
    TERRORIST = "TERRORIST"
    SCRIPT_KIDDIE = "SCRIPT_KIDDIE"
    UNKNOWN = "UNKNOWN"


class ThreatActorSponsor(str, Enum):
    """Threat actor sponsorship levels."""
    STATE_SPONSORED = "STATE_SPONSORED"
    STATE_AFFILIATED = "STATE_AFFILIATED"
    CRIMINALLY_MOTIVATED = "CRIMINALLY_MOTIVATED"
    FINANCIALLY_MOTIVATED = "FINANCIALLY_MOTIVATED"
    IDEOLOGICALLY_MOTIVATED = "IDEOLOGICALLY_MOTIVATED"
    UNSPONSORED = "UNSPONSORED"


class CampaignStatus(str, Enum):
    """Campaign status."""
    EMERGING = "EMERGING"
    ACTIVE = "ACTIVE"
    PEAKED = "PEAKED"
    DECLINING = "DECLINING"
    DORMANT = "DORMANT"
    DISRUPTED = "DISRUPTED"


class AttributionConfidence(str, Enum):
    """Attribution confidence levels."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNATTRIBUTED = "UNATTRIBUTED"


class RiskSeverity(str, Enum):
    """Risk severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


@dataclass
class ThreatActor:
    """Threat actor profile.
    
    Attributes:
        actor_id: Unique identifier
        name: Actor name/alias
        type: Type of threat actor
        sponsor: Sponsorship level
        country: Country of origin
        description: Actor description
        capabilities: List of capabilities
        targets: Known targets
        ttps: Tactics, techniques, and procedures
        associated_actors: Related actors
        active_since: When actor became active
        last_activity: Last known activity
        threat_level: Overall threat level
    """
    actor_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    aliases: List[str] = field(default_factory=list)
    type: ThreatActorType = ThreatActorType.UNKNOWN
    sponsor: ThreatActorSponsor = ThreatActorSponsor.UNSPONSORED
    country: Optional[str] = None
    country_code: Optional[str] = None
    description: str = ""
    capabilities: List[str] = field(default_factory=list)
    primary_targets: List[str] = field(default_factory=list)
    ttps: List[Dict[str, Any]] = field(default_factory=list)
    associated_actor_ids: List[str] = field(default_factory=list)
    suspected_attacks: int = 0
    confirmed_attacks: int = 0
    active_since: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    threat_level: RiskSeverity = RiskSeverity.MEDIUM
    confidence: AttributionConfidence = AttributionConfidence.MEDIUM
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "actor_id": self.actor_id,
            "name": self.name,
            "aliases": self.aliases,
            "type": self.type.value,
            "sponsor": self.sponsor.value,
            "country": self.country,
            "country_code": self.country_code,
            "description": self.description,
            "capabilities": self.capabilities,
            "primary_targets": self.primary_targets,
            "ttps": self.ttps,
            "associated_actor_ids": self.associated_actor_ids,
            "suspected_attacks": self.suspected_attacks,
            "confirmed_attacks": self.confirmed_attacks,
            "active_since": self.active_since.isoformat() if self.active_since else None,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "threat_level": self.threat_level.value,
            "confidence": self.confidence.value,
            "metadata": self.metadata,
        }


@dataclass
class Campaign:
    """Attack campaign model.
    
    Attributes:
        campaign_id: Unique identifier
        name: Campaign name
        description: Campaign description
        status: Current status
        start_date: Campaign start date
        end_date: Campaign end date
        threat_actors: Involved threat actors
        target_sectors: Targeted industry sectors
        target_regions: Targeted geographic regions
        attack_types: Types of attacks used
        scale: Campaign scale
        impact: Estimated impact
    """
    campaign_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    status: CampaignStatus = CampaignStatus.EMERGING
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    threat_actor_ids: List[str] = field(default_factory=list)
    target_sectors: List[str] = field(default_factory=list)
    target_regions: List[str] = field(default_factory=list)
    attack_types: List[str] = field(default_factory=list)
    scale: str = "MEDIUM"  # SMALL, MEDIUM, LARGE, MASSIVE
    estimated_victims: int = 0
    estimated_financial_impact: float = 0.0
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    attribution_confidence: AttributionConfidence = AttributionConfidence.LOW
    discovered_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "threat_actor_ids": self.threat_actor_ids,
            "target_sectors": self.target_sectors,
            "target_regions": self.target_regions,
            "attack_types": self.attack_types,
            "scale": self.scale,
            "estimated_victims": self.estimated_victims,
            "estimated_financial_impact": self.estimated_financial_impact,
            "indicators": self.indicators,
            "ttps": self.ttps,
            "attribution_confidence": self.attribution_confidence.value,
            "discovered_date": self.discovered_date.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class Attribution:
    """Campaign attribution data.
    
    Attributes:
        attribution_id: Unique identifier
        campaign_id: Related campaign
        actor_id: Attributed threat actor
        confidence: Attribution confidence
        evidence: Attribution evidence
        alternative_actors: Alternative possible actors
        attribution_date: When attribution was made
    """
    attribution_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    campaign_id: str = ""
    primary_actor_id: Optional[str] = None
    secondary_actor_ids: List[str] = field(default_factory=list)
    confidence: AttributionConfidence = AttributionConfidence.LOW
    evidence_types: List[str] = field(default_factory=list)
    evidence_summary: str = ""
    alternative_hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    attribution_method: str = ""
    analyst_notes: str = ""
    attribution_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_reviewed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "attribution_id": self.attribution_id,
            "campaign_id": self.campaign_id,
            "primary_actor_id": self.primary_actor_id,
            "secondary_actor_ids": self.secondary_actor_ids,
            "confidence": self.confidence.value,
            "evidence_types": self.evidence_types,
            "evidence_summary": self.evidence_summary,
            "alternative_hypotheses": self.alternative_hypotheses,
            "attribution_method": self.attribution_method,
            "analyst_notes": self.analyst_notes,
            "attribution_date": self.attribution_date.isoformat(),
            "last_reviewed": self.last_reviewed.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class ThreatProfile:
    """Entity threat profile.
    
    Attributes:
        profile_id: Unique identifier
        entity_type: Type of entity (organization, sector, region)
        entity_id: Entity identifier
        threat_score: Overall threat score
        threat_actors: Relevant threat actors
        active_campaigns: Active campaigns targeting entity
        risk_factors: Risk contributing factors
        recommended_mitigations: Mitigation recommendations
    """
    profile_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: str = ""
    entity_id: str = ""
    entity_name: str = ""
    threat_score: float = 0.0
    threat_actors: List[Dict[str, Any]] = field(default_factory=list)
    active_campaigns: List[str] = field(default_factory=list)
    historical_incidents: int = 0
    risk_factors: List[Dict[str, Any]] = field(default_factory=list)
    recommended_mitigations: List[str] = field(default_factory=list)
    last_assessed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "profile_id": self.profile_id,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "entity_name": self.entity_name,
            "threat_score": self.threat_score,
            "threat_actors": self.threat_actors,
            "active_campaigns": self.active_campaigns,
            "historical_incidents": self.historical_incidents,
            "risk_factors": self.risk_factors,
            "recommended_mitigations": self.recommended_mitigations,
            "last_assessed": self.last_assessed.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class AttackPattern:
    """Known attack pattern.
    
    Attributes:
        pattern_id: Unique identifier
        name: Pattern name
        category: Pattern category
        description: Pattern description
        mitre_attack_id: MITRE ATT&CK technique ID
        indicators: IOCs for this pattern
        detection_rules: Detection rule references
        affected_sectors: Sectors commonly affected
    """
    pattern_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: str = ""
    description: str = ""
    mitre_attack_id: Optional[str] = None
    mitre_attack_name: Optional[str] = None
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    detection_rules: List[str] = field(default_factory=list)
    affected_sectors: List[str] = field(default_factory=list)
    observed_frequency: int = 0
    effectiveness_rating: float = 0.0
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "pattern_id": self.pattern_id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "mitre_attack_id": self.mitre_attack_id,
            "mitre_attack_name": self.mitre_attack_name,
            "indicators": self.indicators,
            "detection_rules": self.detection_rules,
            "affected_sectors": self.affected_sectors,
            "observed_frequency": self.observed_frequency,
            "effectiveness_rating": self.effectiveness_rating,
            "first_observed": self.first_observed.isoformat() if self.first_observed else None,
            "last_observed": self.last_observed.isoformat() if self.last_observed else None,
            "metadata": self.metadata,
        }


@dataclass
class RiskAssessment:
    """Risk assessment result.
    
    Attributes:
        assessment_id: Unique identifier
        entity_type: Type of entity assessed
        entity_id: Entity identifier
        risk_score: Overall risk score
        risk_level: Risk severity level
        threat_actors: Relevant threat actors
        attack_likelihood: Probability of attack
        potential_impact: Potential impact of attack
        risk_factors: Contributing risk factors
        recommended_actions: Risk mitigation actions
    """
    assessment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: str = ""
    entity_id: str = ""
    risk_score: float = 0.0
    risk_level: RiskSeverity = RiskSeverity.MEDIUM
    threat_actors: List[str] = field(default_factory=list)
    active_campaigns: List[str] = field(default_factory=list)
    attack_likelihood: float = 0.0
    potential_impact: float = 0.0
    risk_factors: List[Dict[str, Any]] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    assessment_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    next_assessment: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "assessment_id": self.assessment_id,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "threat_actors": self.threat_actors,
            "active_campaigns": self.active_campaigns,
            "attack_likelihood": self.attack_likelihood,
            "potential_impact": self.potential_impact,
            "risk_factors": self.risk_factors,
            "recommended_actions": self.recommended_actions,
            "assessment_date": self.assessment_date.isoformat(),
            "next_assessment": self.next_assessment.isoformat() if self.next_assessment else None,
            "metadata": self.metadata,
        }


@dataclass
class ThreatRelationship:
    """Relationship between threats.
    
    Attributes:
        relationship_id: Unique identifier
        source_type: Source entity type
        source_id: Source entity ID
        target_type: Target entity type
        target_id: Target entity ID
        relationship_type: Type of relationship
        strength: Relationship strength (0-1)
        description: Relationship description
    """
    relationship_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_type: str = ""
    source_id: str = ""
    target_type: str = ""
    target_id: str = ""
    relationship_type: str = ""
    strength: float = 1.0
    description: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    confidence: AttributionConfidence = AttributionConfidence.MEDIUM
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "relationship_id": self.relationship_id,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "relationship_type": self.relationship_type,
            "strength": self.strength,
            "description": self.description,
            "evidence": self.evidence,
            "confidence": self.confidence.value,
            "first_observed": self.first_observed.isoformat() if self.first_observed else None,
            "last_observed": self.last_observed.isoformat() if self.last_observed else None,
            "metadata": self.metadata,
        }