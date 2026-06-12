"""
Autonomous Security Operations Models.

Models for autonomous SOC platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class IncidentStatus(str, Enum):
    """Incident status."""
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    RESPONDING = "responding"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Severity(str, Enum):
    """Incident severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PlaybookStatus(str, Enum):
    """Playbook status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


class AlertStatus(str, Enum):
    """Alert status."""
    NEW = "new"
    TRIAGED = "triaged"
    ESCALATED = "escalated"
    DISMISSED = "dismissed"
    INCIDENT = "incident"


@dataclass
class Alert:
    """Security alert."""
    alert_id: str
    title: str
    description: str
    severity: Severity
    source: str
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    status: AlertStatus = AlertStatus.NEW
    triage_score: float = 0.0
    assigned_to: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Incident:
    """Security incident."""
    incident_id: str
    title: str
    description: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.NEW
    alerts: List[str] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    responders: List[str] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None


@dataclass
class Playbook:
    """Response playbook."""
    playbook_id: str
    name: str
    description: str
    trigger_conditions: Dict[str, Any]
    steps: List[Dict[str, Any]]
    status: PlaybookStatus = PlaybookStatus.ACTIVE
    executed_count: int = 0
    success_rate: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class PlaybookExecution:
    """Playbook execution record."""
    execution_id: str
    playbook_id: str
    incident_id: str
    status: str = "pending"
    current_step: int = 0
    results: List[Dict[str, Any]] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None


@dataclass
class ThreatHunt:
    """Threat hunt session."""
    hunt_id: str
    name: str
    hypothesis: str
    created_by: str
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "planning"
    findings: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CorrelationRule:
    """Threat correlation rule."""
    rule_id: str
    name: str
    conditions: List[Dict[str, Any]]
    severity: Severity
    enabled: bool = True
    match_count: int = 0


@dataclass
class SOCMetrics:
    """SOC metrics."""
    total_incidents: int = 0
    open_incidents: int = 0
    resolved_incidents: int = 0
    avg_response_time_minutes: float = 0.0
    alerts_processed: int = 0
    automated_responses: int = 0
    calculated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


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