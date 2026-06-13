"""
Global Threat Forecasting Platform - Data Models
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class ThreatForecast(BaseModel):
    """Threat forecast."""
    forecast_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    threat_type: str
    description: str
    predicted_impact: str
    confidence: float = 0.0
    time_horizon_days: int = 30
    regions: List[str] = Field(default_factory=list)
    industries: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CampaignPrediction(BaseModel):
    """Campaign prediction."""
    prediction_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign_name: str
    attack_vector: str
    likelihood: float = 0.0
    expected_scale: str
    target_sectors: List[str] = Field(default_factory=list)
    predicted_start: datetime
    predicted_end: Optional[datetime] = None


class TrendAnalysis(BaseModel):
    """Trend analysis."""
    trend_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    metric_name: str
    trend_direction: str
    change_percentage: float = 0.0
    data_points: int = 0
    significance: str = "MEDIUM"
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EconomicImpact(BaseModel):
    """Economic impact."""
    impact_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    threat_type: str
    estimated_loss_min: float = 0.0
    estimated_loss_max: float = 0.0
    affected_sectors: List[str] = Field(default_factory=list)
    duration_months: int = 0
    confidence: float = 0.0


class AttackPrediction(BaseModel):
    """Attack prediction."""
    prediction_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    attack_type: str
    precursor_indicators: List[str] = Field(default_factory=list)
    probability: float = 0.0
    severity: str = "MEDIUM"
    recommended_actions: List[str] = Field(default_factory=list)


class RiskForecast(BaseModel):
    """Risk forecast."""
    forecast_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    risk_category: str
    risk_level: str
    forecast_value: float = 0.0
    confidence: float = 0.0
    factors: Dict[str, float] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ForecastingMetrics(BaseModel):
    """Forecasting metrics."""
    total_forecasts: int = 0
    active_predictions: int = 0
    accuracy_rate: float = 0.0
    threat_categories_tracked: int = 0
