"""
Security Intelligence Mesh Models.

Models for distributed enterprise intelligence mesh.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class NodeType(str, Enum):
    """Types of mesh nodes."""
    FRAUD = "fraud"
    AML = "aml"
    CYBER = "cyber"
    COMPLIANCE = "compliance"
    THREAT_INTEL = "threat_intel"
    INVESTIGATION = "investigation"
    GOVERNANCE = "governance"
    RISK = "risk"


class NodeStatus(str, Enum):
    """Node status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEGRADED = "degraded"
    SUSPENDED = "suspended"


class IntelligenceType(str, Enum):
    """Types of intelligence."""
    THREAT = "threat"
    INDICATOR = "indicator"
    PATTERN = "pattern"
    CAMPAIGN = "campaign"
    VULNERABILITY = "vulnerability"


class ShareLevel(str, Enum):
    """Intelligence sharing levels."""
    FULL = "full"
    PARTIAL = "partial"
    ANONYMIZED = "anonymized"
    NONE = "none"


@dataclass
class MeshNode:
    """Node in the security intelligence mesh."""
    node_id: str
    node_type: NodeType
    name: str
    endpoint: str
    capabilities: List[str] = field(default_factory=list)
    status: NodeStatus = NodeStatus.ACTIVE
    trust_score: float = 1.0
    shared_intelligence_count: int = 0
    received_intelligence_count: int = 0
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_heartbeat: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Intelligence:
    """Intelligence shared across the mesh."""
    intel_id: str
    source_node: str
    intelligence_type: IntelligenceType
    title: str
    description: str
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.8
    share_level: ShareLevel = ShareLevel.PARTIAL
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None


@dataclass
class IntelligenceRequest:
    """Request for intelligence from the mesh."""
    request_id: str
    requesting_node: str
    request_type: str
    filters: Dict[str, Any] = field(default_factory=dict)
    priority: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class OrchestrationTask:
    """Orchestration task for cross-node coordination."""
    task_id: str
    task_type: str
    source_node: str
    target_nodes: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    result: Optional[Dict[str, Any]] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None


@dataclass
class KnowledgeGraphEntry:
    """Entry in the federated knowledge graph."""
    entry_id: str
    entity_type: str
    entity_id: str
    source_node: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    relationships: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class MeshMetrics:
    """Metrics for mesh health."""
    total_nodes: int = 0
    active_nodes: int = 0
    total_intelligence: int = 0
    intelligence_shared: int = 0
    cross_domain_correlations: int = 0
    automated_responses: int = 0
    calculated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AuditEvent:
    """Audit event for mesh operations."""
    event_id: str
    timestamp: datetime
    user_id: str
    action: str
    node_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    success: bool = True