"""
Data Models for Graph Analytics Platform
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class NodeType(str, Enum):
    """Types of graph nodes."""
    ENTITY = "entity"
    ACCOUNT = "account"
    DEVICE = "device"
    IP_ADDRESS = "ip_address"
    PHONE = "phone"
    EMAIL = "email"
    TRANSACTION = "transaction"
    ALERT = "alert"
    CASE = "case"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"


class EdgeType(str, Enum):
    """Types of graph edges."""
    LINKED_TO = "linked_to"
    SENT_TO = "sent_to"
    RECEIVED_FROM = "received_from"
    COMMUNICATED_WITH = "communicated_with"
    ACCESSED = "accessed"
    SHARED_IP = "shared_ip"
    SHARED_DEVICE = "shared_device"
    SIMILAR_BEHAVIOR = "similar_behavior"
    PART_OF = "part_of"
    ATTRIBUTED_TO = "attributed_to"


class AlgorithmType(str, Enum):
    """Graph analysis algorithm types."""
    BFS = "bfs"
    DFS = "dfs"
    DIJKSTRA = "dijkstra"
    PAGE_RANK = "page_rank"
    BETWEENNESS = "betweenness"
    CLOSENESS = "closeness"
    DEGREE = "degree"
    LOUVAIN = "louvain"
    LABEL_PROPAGATION = "label_propagation"


@dataclass
class GraphNode:
    """Node in the security graph."""
    node_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    node_type: NodeType = NodeType.ENTITY
    label: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    threat_level: str = "low"
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "label": self.label,
            "properties": self.properties,
            "risk_score": self.risk_score,
            "threat_level": self.threat_level,
            "tags": self.tags,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "is_active": self.is_active,
        }


@dataclass
class GraphEdge:
    """Edge connecting graph nodes."""
    edge_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str = ""
    target_id: str = ""
    edge_type: EdgeType = EdgeType.LINKED_TO
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "weight": self.weight,
            "properties": self.properties,
            "created_at": self.created_at,
            "is_active": self.is_active,
        }


@dataclass
class GraphQuery:
    """Query parameters for graph traversal."""
    start_node_id: str = ""
    end_node_id: Optional[str] = None
    algorithm: AlgorithmType = AlgorithmType.BFS
    max_depth: int = 5
    edge_types: List[EdgeType] = field(default_factory=list)
    node_types: List[NodeType] = field(default_factory=list)
    min_weight: float = 0.0
    include_properties: bool = True


@dataclass
class CommunityDetection:
    """Community detection result."""
    community_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    algorithm: AlgorithmType = AlgorithmType.LOUVAIN
    node_ids: List[str] = field(default_factory=list)
    size: int = 0
    density: float = 0.0
    risk_score: float = 0.0
    threat_level: str = "low"
    common_tags: List[str] = field(default_factory=list)
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "community_id": self.community_id,
            "algorithm": self.algorithm.value,
            "node_ids": self.node_ids,
            "size": self.size,
            "density": self.density,
            "risk_score": self.risk_score,
            "threat_level": self.threat_level,
            "common_tags": self.common_tags,
            "detected_at": self.detected_at,
        }


@dataclass
class RiskPropagation:
    """Risk propagation analysis result."""
    propagation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_node_id: str = ""
    affected_nodes: List[str] = field(default_factory=list)
    propagation_depth: int = 0
    risk_scores: Dict[str, float] = field(default_factory=dict)
    propagation_path: List[str] = field(default_factory=list)
    calculated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "propagation_id": self.propagation_id,
            "source_node_id": self.source_node_id,
            "affected_nodes": self.affected_nodes,
            "propagation_depth": self.propagation_depth,
            "risk_scores": self.risk_scores,
            "propagation_path": self.propagation_path,
            "calculated_at": self.calculated_at,
        }


@dataclass
class CentralityMetrics:
    """Centrality metrics for graph analysis."""
    node_id: str = ""
    degree_centrality: float = 0.0
    betweenness_centrality: float = 0.0
    closeness_centrality: float = 0.0
    page_rank: float = 0.0
    eigen_centrality: float = 0.0
    calculated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "degree_centrality": self.degree_centrality,
            "betweenness_centrality": self.betweenness_centrality,
            "closeness_centrality": self.closeness_centrality,
            "page_rank": self.page_rank,
            "eigen_centrality": self.eigen_centrality,
            "calculated_at": self.calculated_at,
        }


@dataclass
class PathAnalysis:
    """Path analysis result."""
    path_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str = ""
    target_id: str = ""
    path: List[str] = field(default_factory=list)
    path_length: int = 0
    total_weight: float = 0.0
    edges: List[GraphEdge] = field(default_factory=list)
    analysis_type: str = "shortest_path"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "path": self.path,
            "path_length": self.path_length,
            "total_weight": self.total_weight,
            "edges": [e.to_dict() for e in self.edges],
            "analysis_type": self.analysis_type,
        }


@dataclass
class GraphStats:
    """Statistics for the graph."""
    total_nodes: int = 0
    total_edges: int = 0
    node_types: Dict[str, int] = field(default_factory=dict)
    edge_types: Dict[str, int] = field(default_factory=dict)
    average_degree: float = 0.0
    graph_density: float = 0.0
    connected_components: int = 0
    average_clustering: float = 0.0
    diameter: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_nodes": self.total_nodes,
            "total_edges": self.total_edges,
            "node_types": self.node_types,
            "edge_types": self.edge_types,
            "average_degree": self.average_degree,
            "graph_density": self.graph_density,
            "connected_components": self.connected_components,
            "average_clustering": self.average_clustering,
            "diameter": self.diameter,
        }
