"""
Metaverse Intelligence Models
Immersive investigation and visualization models.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4


class VisualizationType(Enum):
    """Types of visualizations."""
    NETWORK_GRAPH = "NETWORK_GRAPH"
    GRAPH_3D = "GRAPH_3D"
    HEATMAP = "HEATMAP"
    TIMELINE = "TIMELINE"
    GEO_MAP = "GEO_MAP"
    TREEMAP = "TREEMAP"
    SANKEY = "SANKEY"


class InvestigationStatus(Enum):
    """Investigation status."""
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    CLOSED = "CLOSED"
    ESCALATED = "ESCALATED"


class RiskLevel(Enum):
    """Risk levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


@dataclass
class VisualizationNode:
    """Node for visualization."""
    node_id: str
    label: str
    node_type: str
    position: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    size: float = 1.0
    color: str = "#3498db"
    properties: Dict[str, Any] = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.LOW
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "label": self.label,
            "node_type": self.node_type,
            "position": self.position,
            "size": self.size,
            "color": self.color,
            "properties": self.properties,
            "risk_level": self.risk_level.value,
        }


@dataclass
class VisualizationEdge:
    """Edge for visualization."""
    edge_id: str
    source_id: str
    target_id: str
    edge_type: str
    weight: float = 1.0
    color: str = "#95a5a6"
    label: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type,
            "weight": self.weight,
            "color": self.color,
            "label": self.label,
        }


@dataclass
class InvestigationCase:
    """Investigation case."""
    case_id: str
    title: str
    description: str
    status: InvestigationStatus = InvestigationStatus.ACTIVE
    priority: str = "MEDIUM"
    assigned_investigators: List[str] = field(default_factory=list)
    entities: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "priority": self.priority,
            "assigned_investigators": self.assigned_investigators,
            "entities": self.entities,
            "evidence": self.evidence,
            "timeline": self.timeline,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class FraudRing:
    """Fraud ring detection result."""
    ring_id: str
    members: List[str]
    connections: List[Dict[str, Any]]
    risk_score: float
    ring_type: str
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ring_id": self.ring_id,
            "members": self.members,
            "connections": self.connections,
            "risk_score": self.risk_score,
            "ring_type": self.ring_type,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class VisualizationScene:
    """Complete visualization scene."""
    scene_id: str
    title: str
    visualization_type: VisualizationType
    nodes: List[VisualizationNode] = field(default_factory=list)
    edges: List[VisualizationEdge] = field(default_factory=list)
    camera_position: Tuple[float, float, float] = (0.0, 0.0, 10.0)
    filters: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scene_id": self.scene_id,
            "title": self.title,
            "visualization_type": self.visualization_type.value,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "camera_position": self.camera_position,
            "filters": self.filters,
            "created_at": self.created_at.isoformat(),
        }