"""
Observability & Platform Health Models.

Data models for health monitoring, metrics, alerts, and audits.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid


class ComponentStatus(str, Enum):
    """Component health status."""
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    UNKNOWN = "UNKNOWN"


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlertStatus(str, Enum):
    """Alert status."""
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class ComponentHealth(BaseModel):
    """Component health record."""
    component_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    component_name: str
    component_type: str  # api, database, cache, queue, etc.
    status: ComponentStatus = ComponentStatus.UNKNOWN
    health_score: float = 100.0  # 0-100
    last_check: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    response_time_ms: Optional[float] = None
    error_count: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PerformanceMetric(BaseModel):
    """Performance metric record."""
    metric_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    metric_name: str
    component: str
    value: float
    unit: str  # ms, count, percentage, etc.
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tags: Dict[str, str] = Field(default_factory=dict)


class AlertRule(BaseModel):
    """Alert rule configuration."""
    rule_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    condition: Dict[str, Any] = Field(default_factory=dict)
    severity: AlertSeverity
    enabled: bool = True
    cooldown_seconds: int = 300
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Alert(BaseModel):
    """Alert instance."""
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: Optional[str] = None
    title: str
    description: str
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.ACTIVE
    component: str
    metric_value: Optional[float] = None
    threshold: Optional[float] = None
    triggered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[datetime] = None


class AuditEntry(BaseModel):
    """Audit log entry."""
    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    result: str = "SUCCESS"  # SUCCESS, FAILURE


class DashboardSnapshot(BaseModel):
    """Dashboard snapshot."""
    snapshot_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    overall_health_score: float
    active_alerts: int
    critical_alerts: int
    total_requests: int
    avg_response_time_ms: float
    components_summary: Dict[str, Any] = Field(default_factory=dict)


class Incident(BaseModel):
    """Incident record."""
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: AlertSeverity
    status: str = "OPEN"  # OPEN, INVESTIGATING, RESOLVED, CLOSED
    affected_components: List[str] = Field(default_factory=list)
    alerts: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    created_by: Optional[str] = None