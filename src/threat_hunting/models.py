"""
Data models for AI Threat Hunting & Security Analytics Platform
"""

from __future__ import annotations

import uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone


class HuntState(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ThreatSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IndicatorType(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    BEHAVIOR = "BEHAVIOR"
    VELOCITY = "VELOCITY"
    FINGERPRINT = "FINGERPRINT"


class CampaignStatus(str, Enum):
    ACTIVE = "ACTIVE"
    CONTAINED = "CONTAINED"
    MONITORING = "MONITORING"
    RESOLVED = "RESOLVED"


@dataclass
class ThreatHunt:
    hunt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    query_criteria: Dict[str, Any] = field(default_factory=dict)
    state: HuntState = HuntState.PENDING
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings_count: int = 0
    error_message: Optional[str] = None
    created_by: str = "system"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hunt_id": self.hunt_id,
            "name": self.name,
            "description": self.description,
            "query_criteria": self.query_criteria,
            "state": self.state.value if isinstance(self.state, HuntState) else self.state,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "created_at": self.created_at,
            "findings_count": self.findings_count,
            "error_message": self.error_message,
            "created_by": self.created_by,
        }


@dataclass
class ThreatIndicator:
    indicator_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    indicator_type: IndicatorType = IndicatorType.BEHAVIOR
    value: str = ""
    description: str = ""
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    confidence: float = 0.5
    tags: List[str] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator_id": self.indicator_id,
            "indicator_type": self.indicator_type.value if isinstance(self.indicator_type, IndicatorType) else self.indicator_type,
            "value": self.value,
            "description": self.description,
            "severity": self.severity.value if isinstance(self.severity, ThreatSeverity) else self.severity,
            "confidence": self.confidence,
            "tags": self.tags,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "attributes": self.attributes,
        }


@dataclass
class BehaviorProfile:
    entity_id: str
    entity_type: str = "user"  # user, account, device
    typical_hours: List[int] = field(default_factory=list)
    typical_amount_mean: float = 0.0
    typical_amount_std: float = 0.0
    known_ips: List[str] = field(default_factory=list)
    known_devices: List[str] = field(default_factory=list)
    velocity_limit_per_min: int = 5
    last_updated: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    extra_profile_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "typical_hours": self.typical_hours,
            "typical_amount_mean": self.typical_amount_mean,
            "typical_amount_std": self.typical_amount_std,
            "known_ips": self.known_ips,
            "known_devices": self.known_devices,
            "velocity_limit_per_min": self.velocity_limit_per_min,
            "last_updated": self.last_updated,
            "extra_profile_data": self.extra_profile_data,
        }


@dataclass
class ThreatCampaign:
    campaign_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    status: CampaignStatus = CampaignStatus.ACTIVE
    severity: ThreatSeverity = ThreatSeverity.HIGH
    associated_entities: List[str] = field(default_factory=list)  # entity IDs
    associated_indicators: List[str] = field(default_factory=list)  # indicator IDs
    first_detected: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_active: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "description": self.description,
            "status": self.status.value if isinstance(self.status, CampaignStatus) else self.status,
            "severity": self.severity.value if isinstance(self.severity, ThreatSeverity) else self.severity,
            "associated_entities": self.associated_entities,
            "associated_indicators": self.associated_indicators,
            "first_detected": self.first_detected,
            "last_active": self.last_active,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


@dataclass
class AttackPath:
    path_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    nodes: List[Dict[str, Any]] = field(default_factory=list)  # [{'id': ..., 'type': ...}]
    edges: List[Dict[str, Any]] = field(default_factory=list)  # [{'from': ..., 'to': ..., 'type': ...}]
    risk_score: float = 0.0
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "nodes": self.nodes,
            "edges": self.edges,
            "risk_score": self.risk_score,
            "discovered_at": self.discovered_at,
            "description": self.description,
        }


@dataclass
class ThreatCorrelation:
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    entities: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    correlation_score: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "name": self.name,
            "entities": self.entities,
            "indicators": self.indicators,
            "correlation_score": self.correlation_score,
            "timestamp": self.timestamp,
            "details": self.details,
        }


@dataclass
class ThreatScore:
    entity_id: str
    entity_type: str = "user"
    score: float = 0.0
    severity: ThreatSeverity = ThreatSeverity.LOW
    breakdown: Dict[str, float] = field(default_factory=dict)
    active_indicators: List[str] = field(default_factory=list)
    calculated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "score": self.score,
            "severity": self.severity.value if isinstance(self.severity, ThreatSeverity) else self.severity,
            "breakdown": self.breakdown,
            "active_indicators": self.active_indicators,
            "calculated_at": self.calculated_at,
        }


@dataclass
class HuntResult:
    result_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    hunt_id: str = ""
    matched_entity_id: str = ""
    matched_entity_type: str = ""
    threat_score: float = 0.0
    indicators: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result_id": self.result_id,
            "hunt_id": self.hunt_id,
            "matched_entity_id": self.matched_entity_id,
            "matched_entity_type": self.matched_entity_type,
            "threat_score": self.threat_score,
            "indicators": self.indicators,
            "details": self.details,
            "timestamp": self.timestamp,
        }
