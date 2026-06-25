from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class ThreatForecastingEngineThreatForecastCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    forecast_id: str = Field(..., description="forecast_id attribute")
    predicted_threat_type: str = Field(..., description="predicted_threat_type attribute")
    likelihood: float = Field(..., description="likelihood attribute")
    target_sectors: List[str] = Field(..., description="target_sectors attribute")

class ThreatForecastingEngineTrendIndicatorCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    indicator_id: str = Field(..., description="indicator_id attribute")
    metric_name: str = Field(..., description="metric_name attribute")
    trend_direction: str = Field(..., description="trend_direction attribute")
    change_percentage: float = Field(..., description="change_percentage attribute")

class ThreatForecastingEngineCampaignPredictionCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    prediction_id: str = Field(..., description="prediction_id attribute")
    actor_group: str = Field(..., description="actor_group attribute")
    predicted_date: str = Field(..., description="predicted_date attribute")
    confidence_level: float = Field(..., description="confidence_level attribute")
