"""
Nexus Platform Models
Unified intelligence platform models.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class IntelligenceLayer(Enum):
    """Intelligence layers in the Nexus platform."""
    FRAUD = "FRAUD"
    THREAT = "THREAT"
    AML = "AML"
    COMPLIANCE = "COMPLIANCE"
    DEFENSE = "DEFENSE"
    PREDICTIVE = "PREDICTIVE"
    REGULATORY = "REGULATORY"
    GOVERNANCE = "GOVERNANCE"
    DIGITAL_TWIN = "DIGITAL_TWIN"
    SUPERGRAPH = "SUPERGRAPH"
    AGENT_SWARM = "AGENT_SWARM"
    METVERSE = "METVERSE"


class NexusStatus(Enum):
    """Nexus platform status."""
    INITIALIZING = "INITIALIZING"
    OPERATIONAL = "OPERATIONAL"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"


class IntegrationStatus(Enum):
    """Integration status for components."""
    AVAILABLE = "AVAILABLE"
    CONNECTED = "CONNECTED"
    ERROR = "ERROR"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass
class LayerStatus:
    """Status of an intelligence layer."""
    layer: IntelligenceLayer
    status: IntegrationStatus
    last_sync: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metrics: Dict[str, float] = field(default_factory=dict)
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer": self.layer.value,
            "status": self.status.value,
            "last_sync": self.last_sync.isoformat(),
            "metrics": self.metrics,
            "error_message": self.error_message,
        }


@dataclass
class NexusCapability:
    """A capability provided by the Nexus platform."""
    capability_id: str
    name: str
    description: str
    layers: List[IntelligenceLayer]
    endpoints: List[str]
    enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "name": self.name,
            "description": self.description,
            "layers": [l.value for l in self.layers],
            "endpoints": self.endpoints,
            "enabled": self.enabled,
        }


@dataclass
class NexusDashboard:
    """Executive dashboard data."""
    dashboard_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    overall_status: NexusStatus = NexusStatus.INITIALIZING
    layer_statuses: List[LayerStatus] = field(default_factory=list)
    key_metrics: Dict[str, float] = field(default_factory=dict)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "dashboard_id": self.dashboard_id,
            "timestamp": self.timestamp.isoformat(),
            "overall_status": self.overall_status.value,
            "layer_statuses": [s.to_dict() for s in self.layer_statuses],
            "key_metrics": self.key_metrics,
            "alerts": self.alerts,
        }


@dataclass
class CrossLayerAnalysis:
    """Cross-layer analysis result."""
    analysis_id: str
    source_layers: List[IntelligenceLayer]
    target_entity: str
    insights: List[str]
    risk_score: float
    recommendations: List[str]
    confidence: float
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "source_layers": [l.value for l in self.source_layers],
            "target_entity": self.target_entity,
            "insights": self.insights,
            "risk_score": self.risk_score,
            "recommendations": self.recommendations,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat(),
        }