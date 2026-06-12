"""
AegisGraph Sentinel Infinity Models.

Unified models for the infinity platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ComponentType(str, Enum):
    """Component types in infinity platform."""
    FRAUD_DETECTION = "fraud_detection"
    AML = "aml"
    CYBER_SECURITY = "cyber_security"
    THREAT_INTEL = "threat_intel"
    AUTONOMOUS_SECOPS = "autonomous_secops"
    DIGITAL_TWIN = "digital_twin"
    QUANTUM_SECURITY = "quantum_security"
    DRP = "drp"
    CTI = "cti"
    FININTEL = "finintel"
    SECURITY_MESH = "security_mesh"


class IntegrationStatus(str, Enum):
    """Integration status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    SYNCING = "syncing"


class RiskLevel(str, Enum):
    """Risk levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Component:
    """Platform component."""
    component_id: str
    component_type: ComponentType
    name: str
    status: IntegrationStatus = IntegrationStatus.ACTIVE
    last_sync: Optional[datetime] = None
    health_score: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UnifiedIntelligence:
    """Unified intelligence record."""
    intel_id: str
    intelligence_type: str
    title: str
    description: str
    severity: RiskLevel
    sources: List[str] = field(default_factory=list)
    confidence: float = 0.5
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    correlated: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class InfinityDashboard:
    """Infinity platform dashboard data."""
    total_intelligence: int = 0
    active_threats: int = 0
    fraud_alerts: int = 0
    cyber_alerts: int = 0
    aml_alerts: int = 0
    components_healthy: int = 0
    components_total: int = 0
    unified_threats: int = 0
    automated_responses: int = 0
    calculated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CrossDomainCorrelation:
    """Cross-domain threat correlation."""
    correlation_id: str
    correlation_type: str
    description: str
    related_intelligence: List[str] = field(default_factory=list)
    confidence: float = 0.5
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AuditEvent:
    """Audit event."""
    event_id: str
    timestamp: datetime
    user_id: str
    action: str
    resource_type: str
    resource_id: str
    details: Dict[str, Any] = field(default_factory=dict)
    success: bool = True