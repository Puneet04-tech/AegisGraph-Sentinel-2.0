from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class SecurityIntelligenceNexusGlobalIntelligenceHubStateCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    hub_id: str = Field(..., description="hub_id attribute")
    connected_domains: List[str] = Field(..., description="connected_domains attribute")
    ingestion_rate: float = Field(..., description="ingestion_rate attribute")
    is_healthy: bool = Field(..., description="is_healthy attribute")

class SecurityIntelligenceNexusUnifiedAnalyticsReportCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    report_id: str = Field(..., description="report_id attribute")
    generated_by: str = Field(..., description="generated_by attribute")
    domain_coverage: Dict[str, float] = Field(..., description="domain_coverage attribute")
    threat_count: int = Field(..., description="threat_count attribute")

class SecurityIntelligenceNexusIntelligenceRouteCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    route_id: str = Field(..., description="route_id attribute")
    source_domain: str = Field(..., description="source_domain attribute")
    target_domain: str = Field(..., description="target_domain attribute")
    priority: str = Field(..., description="priority attribute")
