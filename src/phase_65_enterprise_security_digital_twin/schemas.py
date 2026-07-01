from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class SecurityDigitalTwinDigitalTwinStateCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    state_id: str = Field(..., description="state_id attribute")
    entity_id: str = Field(..., description="entity_id attribute")
    posture_score: float = Field(..., description="posture_score attribute")
    anomaly_detected: bool = Field(..., description="anomaly_detected attribute")

class SecurityDigitalTwinRiskVisualizationNodeCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    node_id: str = Field(..., description="node_id attribute")
    asset_name: str = Field(..., description="asset_name attribute")
    risk_level: str = Field(..., description="risk_level attribute")
    x_y_coordinates: List[float] = Field(..., description="x_y_coordinates attribute")

class SecurityDigitalTwinForecastingScenarioCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    scenario_id: str = Field(..., description="scenario_id attribute")
    predicted_impact: str = Field(..., description="predicted_impact attribute")
    forecasting_accuracy: float = Field(..., description="forecasting_accuracy attribute")
    is_critical: bool = Field(..., description="is_critical attribute")
