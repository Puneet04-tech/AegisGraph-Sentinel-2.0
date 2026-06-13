"""
Data Models for Data Lineage & Provenance Platform
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class RecordType(str, Enum):
    """Types of records that can be tracked in the lineage system."""
    INTELLIGENCE = "intelligence"
    INVESTIGATION = "investigation"
    THREAT_INDICATOR = "threat_indicator"
    FRAUD_SIGNAL = "fraud_signal"
    COMPLIANCE_EVENT = "compliance_event"
    SECURITY_DECISION = "security_decision"
    CASE_ARTIFACT = "case_artifact"
    RISK_ASSESSMENT = "risk_assessment"
    ENTITY_DATA = "entity_data"
    TRANSACTION = "transaction"


class SourceType(str, Enum):
    """Types of data sources."""
    INTERNAL_API = "internal_api"
    EXTERNAL_FEED = "external_feed"
    MANUAL_ENTRY = "manual_entry"
    AUTOMATED_DETECTION = "automated_detection"
    THIRD_PARTY = "third_party"
    USER_INPUT = "user_input"
    SYSTEM_GENERATED = "system_generated"


class TrustLevel(str, Enum):
    """Trust levels for data provenance."""
    VERIFIED = "verified"
    HIGHLY_TRUSTED = "highly_trusted"
    TRUSTED = "trusted"
    UNVERIFIED = "unverified"
    UNTRUSTED = "untrusted"


class ImpactLevel(str, Enum):
    """Impact levels for data dependencies."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


@dataclass
class SourceAttribution:
    """Source attribution for data records."""
    source_id: str
    source_type: SourceType
    source_name: str
    ingestion_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trust_level: TrustLevel = TrustLevel.TRUSTED
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_type": self.source_type.value,
            "source_name": self.source_name,
            "ingestion_timestamp": self.ingestion_timestamp,
            "trust_level": self.trust_level.value,
            "metadata": self.metadata,
        }


@dataclass
class TraceabilityRecord:
    """Record of traceability events."""
    record_id: str
    action: str
    actor: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = field(default_factory=dict)
    previous_state: Optional[str] = None
    new_state: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "action": self.action,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "details": self.details,
            "previous_state": self.previous_state,
            "new_state": self.new_state,
        }


@dataclass
class LineageNode:
    """Node in the data lineage graph."""
    node_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    record_id: str = ""
    record_type: RecordType = RecordType.INTELLIGENCE
    label: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: int = 1
    is_root: bool = False
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "record_id": self.record_id,
            "record_type": self.record_type.value,
            "label": self.label,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
            "is_root": self.is_root,
            "tags": self.tags,
        }


@dataclass
class LineageEdge:
    """Edge connecting lineage nodes."""
    edge_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_node_id: str = ""
    target_node_id: str = ""
    relationship_type: str = ""
    impact_level: ImpactLevel = ImpactLevel.MEDIUM
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "relationship_type": self.relationship_type,
            "impact_level": self.impact_level.value,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }


@dataclass
class DependencyGraph:
    """Graph of data dependencies."""
    graph_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    root_record_id: str = ""
    nodes: List[LineageNode] = field(default_factory=list)
    edges: List[LineageEdge] = field(default_factory=list)
    depth: int = 0
    total_records: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "root_record_id": self.root_record_id,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "depth": self.depth,
            "total_records": self.total_records,
            "created_at": self.created_at,
        }


@dataclass
class DataRecord:
    """Core data record with lineage information."""
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    record_type: RecordType = RecordType.INTELLIGENCE
    data: Dict[str, Any] = field(default_factory=dict)
    source: Optional[SourceAttribution] = None
    provenance_chain: List[str] = field(default_factory=list)  # List of record IDs
    lineage_nodes: List[LineageNode] = field(default_factory=list)
    traceability_records: List[TraceabilityRecord] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    created_by: str = "system"
    version: int = 1
    is_active: bool = True
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "record_type": self.record_type.value,
            "data": self.data,
            "source": self.source.to_dict() if self.source else None,
            "provenance_chain": self.provenance_chain,
            "lineage_nodes": [n.to_dict() for n in self.lineage_nodes],
            "traceability_records": [t.to_dict() for t in self.traceability_records],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "created_by": self.created_by,
            "version": self.version,
            "is_active": self.is_active,
            "tags": self.tags,
        }


@dataclass
class ProvenanceChain:
    """Complete provenance chain for a data record."""
    chain_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    root_record_id: str = ""
    records: List[DataRecord] = field(default_factory=list)
    edges: List[LineageEdge] = field(default_factory=list)
    total_depth: int = 0
    total_records: int = 0
    chain_integrity: float = 1.0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    verified_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "root_record_id": self.root_record_id,
            "records": [r.to_dict() for r in self.records],
            "edges": [e.to_dict() for e in self.edges],
            "total_depth": self.total_depth,
            "total_records": self.total_records,
            "chain_integrity": self.chain_integrity,
            "created_at": self.created_at,
            "verified_at": self.verified_at,
        }


@dataclass
class ImpactAnalysis:
    """Analysis of data record impact."""
    analysis_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    record_id: str = ""
    impacted_records: List[str] = field(default_factory=list)
    impacted_entities: List[str] = field(default_factory=list)
    downstream_effects: Dict[str, Any] = field(default_factory=dict)
    upstream_dependencies: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    impact_level: ImpactLevel = ImpactLevel.MEDIUM
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "record_id": self.record_id,
            "impacted_records": self.impacted_records,
            "impacted_entities": self.impacted_entities,
            "downstream_effects": self.downstream_effects,
            "upstream_dependencies": self.upstream_dependencies,
            "risk_score": self.risk_score,
            "impact_level": self.impact_level.value,
            "created_at": self.created_at,
        }


@dataclass
class LineageStats:
    """Statistics for the lineage system."""
    total_records: int = 0
    total_nodes: int = 0
    total_edges: int = 0
    average_depth: float = 0.0
    max_depth: int = 0
    records_by_type: Dict[str, int] = field(default_factory=dict)
    sources_by_type: Dict[str, int] = field(default_factory=dict)
    chain_integrity: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_records": self.total_records,
            "total_nodes": self.total_nodes,
            "total_edges": self.total_edges,
            "average_depth": self.average_depth,
            "max_depth": self.max_depth,
            "records_by_type": self.records_by_type,
            "sources_by_type": self.sources_by_type,
            "chain_integrity": self.chain_integrity,
        }


@dataclass
class LineageQuery:
    """Query parameters for lineage search."""
    record_id: Optional[str] = None
    record_type: Optional[RecordType] = None
    source_type: Optional[SourceType] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    depth_limit: int = 10
    include_derivatives: bool = True
    include_ancestors: bool = True
