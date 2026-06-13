"""
Security Exposure Management Platform - Data Models

Enterprise-wide security exposure tracking and management.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class ExposureSeverity(str, Enum):
    """Exposure severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ExposureCategory(str, Enum):
    """Exposure categories."""
    VULNERABILITY = "VULNERABILITY"
    MISCONFIGURATION = "MISCONFIGURATION"
    WEAK_CREDENTIAL = "WEAK_CREDENTIAL"
    EXPOSED_ASSET = "EXPOSED_ASSET"
    COMPLIANCE_VIOLATION = "COMPLIANCE_VIOLATION"
    IDENTITY_RISK = "IDENTITY_RISK"
    NETWORK_EXPOSURE = "NETWORK_EXPOSURE"
    DATA_EXPOSURE = "DATA_EXPOSURE"
    API_EXPOSURE = "API_EXPOSURE"
    CLOUD_MISCONFIG = "CLOUD_MISCONFIG"


class ExposureStatus(str, Enum):
    """Exposure status."""
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    REMEDIATED = "REMEDIATED"
    ACCEPTED = "ACCEPTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    DEFERRED = "DEFERRED"


class AssetType(str, Enum):
    """Asset types."""
    SERVER = "SERVER"
    WORKSTATION = "WORKSTATION"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    CONTAINER = "CONTAINER"
    DATABASE = "DATABASE"
    APPLICATION = "APPLICATION"
    API = "API"
    IDENTITY = "IDENTITY"
    NETWORK_DEVICE = "NETWORK_DEVICE"
    IOT_DEVICE = "IOT_DEVICE"


class Exposure(BaseModel):
    """Security exposure."""
    exposure_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: ExposureSeverity
    category: ExposureCategory
    status: ExposureStatus = ExposureStatus.OPEN
    asset_id: str
    asset_type: AssetType
    affected_assets: List[str] = Field(default_factory=list)
    exposure_score: float = 0.0
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    affected_cwe: List[str] = Field(default_factory=list)
    affected_cpe: List[str] = Field(default_factory=list)
    business_impact: str = ""
    risk_factors: Dict[str, float] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    remediation_deadline: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AssetInventory(BaseModel):
    """Asset inventory entry."""
    asset_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    asset_type: AssetType
    owner: str
    department: str
    criticality: str = "MEDIUM"
    exposure_count: int = 0
    highest_severity: ExposureSeverity = ExposureSeverity.INFORMATIONAL
    tags: List[str] = Field(default_factory=list)
    ip_addresses: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    cloud_provider: Optional[str] = None
    cloud_resource_id: Optional[str] = None
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackSurface(BaseModel):
    """Attack surface analysis."""
    surface_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str
    entry_points: List[Dict[str, Any]] = Field(default_factory=list)
    exposed_services: List[str] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    attack_vector_score: float = 0.0
    exposure_pathways: List[Dict[str, Any]] = Field(default_factory=list)
    blast_radius: float = 0.0
    calculated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RemediationTask(BaseModel):
    """Remediation task."""
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    exposure_id: str
    title: str
    description: str
    assigned_to: Optional[str] = None
    priority: ExposureSeverity
    status: str = "PENDING"
    estimated_effort_hours: float = 0.0
    actual_effort_hours: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    due_date: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    dependencies: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecurityPosture(BaseModel):
    """Security posture assessment."""
    posture_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    overall_score: float = 0.0
    exposure_count_by_severity: Dict[str, int] = Field(default_factory=dict)
    total_exposures: int = 0
    remediated_exposures: int = 0
    exposure_trend: str = "STABLE"
    risk_distribution: Dict[str, float] = Field(default_factory=dict)
    compliance_score: float = 0.0
    assessment_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    recommendations: List[str] = Field(default_factory=list)


class ExposureMetrics(BaseModel):
    """Exposure metrics."""
    total_exposures: int = 0
    critical_exposures: int = 0
    high_exposures: int = 0
    medium_exposures: int = 0
    low_exposures: int = 0
    remediated_exposures: int = 0
    mtt_remediation_hours: float = 0.0
    mean_exposure_score: float = 0.0
    top_exposed_assets: List[Dict[str, Any]] = Field(default_factory=list)
    top_exposure_categories: List[Dict[str, Any]] = Field(default_factory=list)
    exposure_trend: List[Dict[str, Any]] = Field(default_factory=list)
