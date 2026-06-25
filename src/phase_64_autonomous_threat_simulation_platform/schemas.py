from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class ThreatSimulationPlatformThreatScenarioCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    scenario_id: str = Field(..., description="scenario_id attribute")
    scenario_type: str = Field(..., description="scenario_type attribute")
    steps: List[str] = Field(..., description="steps attribute")
    target_assets: List[str] = Field(..., description="target_assets attribute")

class ThreatSimulationPlatformFraudSimulationCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    simulation_id: str = Field(..., description="simulation_id attribute")
    campaign_type: str = Field(..., description="campaign_type attribute")
    detection_rate: float = Field(..., description="detection_rate attribute")
    status: str = Field(..., description="status attribute")

class ThreatSimulationPlatformResilienceMetricsCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    metrics_id: str = Field(..., description="metrics_id attribute")
    scenario_id: str = Field(..., description="scenario_id attribute")
    breach_probability: float = Field(..., description="breach_probability attribute")
    mitigation_score: float = Field(..., description="mitigation_score attribute")
