"""
Threat Supergraph Models
Planet-scale intelligence graph connecting fraud entities, cyber threats, and more.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class EntityType(Enum):
    """Entity types in the supergraph."""
    FRAUD_ENTITY = "FRAUD_ENTITY"
    THREAT_ACTOR = "THREAT_ACTOR"
    CAMPAIGN = "CAMPAIGN"
    ORGANIZATION = "ORGANIZATION"
    DEVICE = "DEVICE"
    IP_ADDRESS = "IP_ADDRESS"
    DOMAIN = "DOMAIN"
    EMAIL = "EMAIL"
    ACCOUNT = "ACCOUNT"
    TRANSACTION = "TRANSACTION"
    MULE_ACCOUNT = "MULE_ACCOUNT"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    MALWARE = "MALWARE"
    VULNERABILITY = "VULNERABILITY"
    INDICATOR = "INDICATOR"
    INTEL_SOURCE = "INTEL_SOURCE"
    DIGITAL_IDENTITY = "DIGITAL_IDENTITY"


class RelationshipType(Enum):
    """Relationship types between entities."""
    COMMUNICATES_WITH = "COMMUNICATES_WITH"
    HOSTS = "HOSTS"
    CONTROLS = "CONTROLS"
    BELONGS_TO = "BELONGS_TO"
    PART_OF = "PART_OF"
    ATTRIBUTED_TO = "ATTRIBUTED_TO"
    TARGETS = "TARGETS"
    EXFILTRATES = "EXFILTRATES"
    IMITATES = "IMITATES"
    RELATED_TO = "RELATED_TO"
    SIMILAR_TO = "SIMILAR_TO"
    COLLATERAL = "COLLATERAL"


class GraphAnalysisType(Enum):
    """Types of graph analysis."""
    COMMUNITY_DETECTION = "COMMUNITY_DETECTION"
    CENTRALITY = "CENTRALITY"
    PATH_ANALYSIS = "PATH_ANALYSIS"
    CLUSTERING = "CLUSTERING"
    ANOMALY_DETECTION = "ANOMALY_DETECTION"
    INFLUENCE_SCORING = "INFLUENCE_SCORING"


class ConfidenceLevel(Enum):
    """Confidence levels for relationships."""
    CONFIRMED = "CONFIRMED"
    HIGHLY_LIKELY = "HIGHLY_LIKELY"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class SupergraphNode:
    """Node in the threat supergraph."""
    node_id: str
    entity_type: EntityType
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    labels: List[str] = field(default_factory=list)
    threat_score: float = 0.0
    risk_level: str = "UNKNOWN"
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "entity_type": self.entity_type.value,
            "name": self.name,
            "properties": self.properties,
            "labels": self.labels,
            "threat_score": self.threat_score,
            "risk_level": self.risk_level,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "tags": self.tags,
            "metadata": self.metadata,
        }


@dataclass
class SupergraphEdge:
    """Edge in the threat supergraph."""
    edge_id: str
    source_id: str
    target_id: str
    relationship_type: RelationshipType
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship_type": self.relationship_type.value,
            "confidence": self.confidence.value,
            "weight": self.weight,
            "properties": self.properties,
            "discovered_at": self.discovered_at.isoformat(),
            "evidence": self.evidence,
        }


@dataclass
class GraphQuery:
    """Query for the supergraph."""
    query_id: str = field(default_factory=lambda: str(uuid4()))
    entity_types: List[EntityType] = field(default_factory=list)
    relationship_types: List[RelationshipType] = field(default_factory=list)
    property_filters: Dict[str, Any] = field(default_factory=dict)
    max_hops: int = 3
    limit: int = 1000
    analysis_type: Optional[GraphAnalysisType] = None
    time_range: Optional[tuple] = None


@dataclass
class GraphAnalysis:
    """Result of graph analysis."""
    analysis_id: str = field(default_factory=lambda: str(uuid4()))
    analysis_type: GraphAnalysisType = GraphAnalysisType.CLUSTERING
    entities: List[str] = field(default_factory=list)
    communities: List[List[str]] = field(default_factory=list)
    centrality_scores: Dict[str, float] = field(default_factory=dict)
    paths: List[List[str]] = field(default_factory=list)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    confidence: float = 0.0
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "analysis_type": self.analysis_type.value,
            "entities": self.entities,
            "communities": self.communities,
            "centrality_scores": self.centrality_scores,
            "paths": self.paths,
            "anomalies": self.anomalies,
            "recommendations": self.recommendations,
            "confidence": self.confidence,
            "analyzed_at": self.analyzed_at.isoformat(),
        }


@dataclass
class CampaignIntelligence:
    """Campaign intelligence data."""
    campaign_id: str
    name: str
    objective: str
    target_sectors: List[str]
    threat_actors: List[str]
    indicators: List[str]
    ttps: List[str]
    confidence: float
    status: str
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AttackPath:
    """Attack path information."""
    path_id: str
    source_entity: str
    target_entity: str
    nodes: List[str]
    risk_score: float
    entry_points: List[str]
    exfiltration_points: List[str]
    recommended_mitigations: List[str]