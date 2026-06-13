"""
Insider Threat Intelligence Models.

Data models for insider risk detection and behavior monitoring.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid


class ThreatLevel(str, Enum):
    """Threat level classification."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActivityType(str, Enum):
    """Activity types."""
    LOGIN = "LOGIN"
    FILE_ACCESS = "FILE_ACCESS"
    FILE_DOWNLOAD = "FILE_DOWNLOAD"
    FILE_TRANSFER = "FILE_TRANSFER"
    EMAIL = "EMAIL"
    DATA_EXPORT = "DATA_EXPORT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"


class InsiderProfile(BaseModel):
    """Insider threat profile."""
    profile_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    employee_id: str
    department: str
    role: str
    risk_score: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.LOW
    risk_factors: List[str] = Field(default_factory=list)
    baseline_established: bool = False
    last_evaluated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BehavioralBaseline(BaseModel):
    """Behavioral baseline for comparison."""
    baseline_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    employee_id: str
    activity_type: ActivityType
    avg_frequency: float
    avg_duration: float
    typical_hours: List[int] = Field(default_factory=list)
    typical_locations: List[str] = Field(default_factory=list)
    typical_devices: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ActivityRecord(BaseModel):
    """Activity record."""
    activity_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    employee_id: str
    activity_type: ActivityType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resource_accessed: str
    location: str
    device_id: str
    duration_seconds: float = 0.0
    data_volume: int = 0
    anomalies: List[str] = Field(default_factory=list)
    risk_score_contribution: float = 0.0


class ThreatIndicator(BaseModel):
    """Threat indicator."""
    indicator_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    employee_id: str
    indicator_type: str
    severity: ThreatLevel
    description: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float
    related_activities: List[str] = Field(default_factory=list)
    resolved: bool = False


class InsiderCampaign(BaseModel):
    """Insider threat campaign (coordinated activity)."""
    campaign_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    involved_employees: List[str] = Field(default_factory=list)
    threat_type: str
    risk_score: float
    threat_level: ThreatLevel
    indicators: List[str] = Field(default_factory=list)
    timeline: Dict[str, Any] = Field(default_factory=dict)
    status: str = "ACTIVE"  # ACTIVE, INVESTIGATING, CONTAINED, CLOSED
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))