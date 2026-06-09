"""
AegisGraph Sentinel X - Unified Enterprise Ecosystem.

This is the final unified platform combining all AegisGraph modules.
"""

from datetime import datetime, timezone
from typing import Dict, List, Any
from pydantic import BaseModel, Field
import uuid


class PlatformStatus(BaseModel):
    """Overall platform status."""
    version: str = "X.0.0"
    uptime_seconds: float = 0.0
    total_modules: int = 30
    active_modules: int = 30
    health_score: float = 0.95
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IntegrationPoint(BaseModel):
    """Integration point for modules."""
    integration_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_module: str
    target_module: str
    status: str = "ACTIVE"
    last_sync: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class UnifiedDashboard(BaseModel):
    """Unified dashboard data."""
    dashboard_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    fraud_detection_active: bool = True
    aml_monitoring_active: bool = True
    insider_threat_active: bool = True
    compliance_active: bool = True
    metrics: Dict[str, Any] = Field(default_factory=dict)