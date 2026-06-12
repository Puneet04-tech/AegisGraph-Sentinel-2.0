"""
Core data models for Global Fraud Intelligence Knowledge Graph & Federation Platform.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class EntityType(str, Enum):
    """Types of entities in the knowledge graph."""
    ACCOUNT = "account"
    DEVICE = "device"
    IP_ADDRESS = "ip_address"
    EMAIL = "email"
    PHONE = "phone"
    PERSON = "person"
    ORGANIZATION = "organization"
    TRANSACTION = "transaction"
    CARD = "card"
    ADDRESS = "address"
    FRAUD_PATTERN = "fraud_pattern"
    THREAT_ACTOR = "threat_actor"


class ThreatLevel(str, Enum):
    """Threat level classification."""
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IntelligenceSource(str, Enum):
    """Source of intelligence data."""
    INTERNAL = "internal"
    FEDERATION = "federation"
    THREAT_INTEL_PROVIDER = "threat_intel_provider"
    GOVERNMENT = "government"
    INDUSTRY = "industry"
    OPEN_SOURCE = "open_source"


class InvestigationStatus(str, Enum):
    """Status of an investigation case."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING_REVIEW = "pending_review"
    CLOSED = "closed"
    ESCALATED = "escalated"


class FederationStatus(str, Enum):
    """Status of federation partnership."""
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"


class NetworkType(str, Enum):
    """Types of fraud networks."""
    FRAUD_RING = "fraud_ring"
    MULE_NETWORK = "mule_network"
    IDENTITY_theft = "identity_theft"
    CARDING = "carding"
    MONEY_LAUNDERING = "money_laundering"
    ACCOUNT_TAKEOVER = "account_takeover"


class CorrelationStrength(str, Enum):
    """Strength of entity correlation."""
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    DEFINITIVE = "definitive"


@dataclass
class FederatedEntity:
    """Entity shared across federation partners."""
    entity_id: str
    entity_type: EntityType
    federation_id: str
    partner_id: str
    external_id: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    threat_indicators: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_anonymized: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_anonymized(self) -> FederatedEntity:
        """Create anonymized version for sharing."""
        return FederatedEntity(
            entity_id=self.entity_id,
            entity_type=self.entity_type,
            federation_id=self.federation_id,
            partner_id="ANONYMIZED",
            external_id="REDACTED",
            attributes={},
            threat_indicators=self.threat_indicators,
            risk_score=self.risk_score,
            threat_level=self.threat_level,
            first_seen=self.first_seen,
            last_updated=self.last_updated,
            is_anonymized=True,
            metadata={"original_partner": "REDACTED"},
        )


@dataclass
class FraudNetwork:
    """Represents a discovered fraud network."""
    network_id: str
    network_type: NetworkType
    nodes: List[str]
    edges: List[Dict[str, Any]]
    confidence_score: float
    threat_level: ThreatLevel
    member_count: int
    activity_score: float
    first_detected: datetime
    last_activity: datetime
    associated_campaigns: List[str] = field(default_factory=list)
    discovery_method: str = ""
    discovered_by: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatIndicator:
    """Threat indicator shared across federation."""
    indicator_id: str
    indicator_type: str
    value: str
    source: IntelligenceSource
    threat_type: str
    threat_level: ThreatLevel
    confidence: float
    first_seen: datetime
    last_seen: datetime
    expiration: Optional[datetime]
    partner_id: Optional[str]
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if indicator has expired."""
        if self.expiration is None:
            return False
        return datetime.now(timezone.utc) > self.expiration


@dataclass
class FraudCampaign:
    """Multi-institution fraud campaign."""
    campaign_id: str
    campaign_name: str
    threat_type: str
    threat_level: ThreatLevel
    start_date: datetime
    end_date: Optional[datetime]
    affected_institutions: List[str]
    victim_count: int
    total_loss: float
    confidence_score: float
    indicators: List[ThreatIndicator]
    associated_networks: List[str]
    discovery_date: datetime
    status: str = "active"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InvestigationCase:
    """Investigation case for fraud analysis."""
    case_id: str
    title: str
    description: str
    status: InvestigationStatus
    priority: int
    created_by: str
    assigned_to: Optional[str]
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime]
    entities: List[str] = field(default_factory=list)
    networks: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    related_cases: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class KnowledgeGraphNode:
    """Node in the knowledge graph."""
    node_id: str
    entity_type: EntityType
    properties: Dict[str, Any]
    labels: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class KnowledgeGraphEdge:
    """Edge in the knowledge graph."""
    edge_id: str
    source_id: str
    target_id: str
    relationship_type: str
    properties: Dict[str, Any]
    weight: float = 1.0
    confidence: float = 1.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskPropagation:
    """Risk propagation through the graph."""
    propagation_id: str
    source_entity_id: str
    target_entity_id: str
    propagation_path: List[str]
    risk_score: float
    propagation_strength: float
    hop_count: int
    risk_factors: List[str]
    calculated_at: datetime
    expires_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatCorrelation:
    """Correlation between threat indicators."""
    correlation_id: str
    indicator_1_id: str
    indicator_2_id: str
    correlation_type: str
    strength: CorrelationStrength
    confidence: float
    shared_indicators: List[str]
    discovered_at: datetime
    verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FederationPartner:
    """Federation partner organization."""
    partner_id: str
    organization_name: str
    organization_type: str
    status: FederationStatus
    trust_level: int
    api_endpoint: Optional[str]
    api_key_hash: Optional[str]
    joined_at: datetime
    last_sync: Optional[datetime]
    shared_entities: int = 0
    received_intelligence: int = 0
    sharing_policy: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditRecord:
    """Audit record for intelligence operations."""
    record_id: str
    operation: str
    user_id: str
    partner_id: Optional[str]
    entity_ids: List[str]
    timestamp: datetime
    ip_address: str
    user_agent: str
    success: bool
    error_message: Optional[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IntelligenceQuery:
    """Query for federated intelligence search."""
    query_id: str
    query_type: str
    entity_type: Optional[EntityType]
    attributes: Dict[str, Any]
    threat_levels: List[ThreatLevel]
    sources: List[IntelligenceSource]
    date_range_start: Optional[datetime]
    date_range_end: Optional[datetime]
    include_anonymized: bool = True
    max_results: int = 100
    requesting_partner_id: Optional[str] = None


@dataclass
class IntelligenceShare:
    """Intelligence sharing record."""
    share_id: str
    entity: FederatedEntity
    shared_by: str
    shared_with: List[str]
    shared_at: datetime
    share_type: str
    is_anonymized: bool
    expires_at: Optional[datetime]
    acknowledged: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphQuery:
    """Query for knowledge graph traversal."""
    query_id: str
    start_node_id: str
    traversal_type: str
    max_depth: int = 3
    relationship_types: List[str] = field(default_factory=list)
    node_filters: Dict[str, Any] = field(default_factory=dict)
    edge_filters: Dict[str, Any] = field(default_factory=dict)
    include_properties: bool = True


@dataclass
class NetworkAnalysisResult:
    """Result of network analysis."""
    network_id: str
    analysis_type: str
    metrics: Dict[str, float]
    communities: List[List[str]]
    central_nodes: List[Dict[str, Any]]
    risk_score: float
    analyzed_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InvestigationReport:
    """Report generated from investigation."""
    report_id: str
    case_id: str
    report_type: str
    summary: str
    findings: List[str]
    recommendations: List[str]
    attached_entities: List[str]
    attached_networks: List[str]
    generated_by: str
    generated_at: datetime
    reviewed_by: Optional[str]
    approved: bool = False


@dataclass
class DashboardMetrics:
    """Dashboard metrics for global intelligence."""
    total_entities: int
    active_threats: int
    federation_partners: int
    campaigns_active: int
    networks_discovered: int
    investigations_open: int
    indicators_shared: int
    indicators_received: int
    avg_risk_score: float
    threat_distribution: Dict[str, int]
    last_updated: datetime


@dataclass
class SharingPolicy:
    """Policy for intelligence sharing."""
    policy_id: str
    partner_id: str
    entity_types_allowed: List[EntityType]
    threat_levels_minimum: List[ThreatLevel]
    anonymization_required: bool
    retention_days: int
    audit_required: bool
    approval_required: bool
    created_at: datetime
    updated_at: datetime
    enabled: bool = True


@dataclass
class CorrelationResult:
    """Result of entity correlation analysis."""
    result_id: str
    primary_entity_id: str
    total_candidates: int
    matches_found: int
    matches: List[EntityMatch]
    avg_score: float
    analyzed_at: datetime


@dataclass
class EntityMatch:
    """Individual entity match from correlation."""
    match_id: str
    entity_1_id: str
    entity_2_id: str
    correlation_score: float
    strength: CorrelationStrength
    match_type: str
    shared_attributes: List[str]
    confidence: float
    discovered_at: datetime
    verified: bool = False