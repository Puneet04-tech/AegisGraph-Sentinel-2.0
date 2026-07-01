from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class FraudIntelligenceFusionCenterCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique identifier")
    tenant_id: str = Field(..., description="Tenant workspace")
    name: str = Field(..., min_length=3, max_length=200)
    status: str = Field(default="ACTIVE")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class FraudIntelligenceFusionCenterEventSchema(BaseModel):
    event_id: str = Field(..., description="Unique event ID")
    record_id: str = Field(..., description="Associated record ID")
    event_type: str = Field(..., description="Type of event")
    severity: str = Field(..., description="Severity level")
    details: Optional[Dict[str, Any]] = Field(default_factory=dict)


class FraudIntelligenceFusionCenterAlertSchema(BaseModel):
    alert_id: str = Field(..., description="Unique alert ID")
    title: str = Field(..., min_length=5, max_length=300)
    severity: str = Field(..., description="Alert severity")
    is_active: bool = Field(default=True)
