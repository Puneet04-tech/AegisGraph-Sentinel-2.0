from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class ThreatForecastingEngineThreatForecast:
    record_id: str
    tenant_id: str
    forecast_id: str
    predicted_threat_type: str
    likelihood: float
    target_sectors: List[str]
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class ThreatForecastingEngineTrendIndicator:
    record_id: str
    tenant_id: str
    indicator_id: str
    metric_name: str
    trend_direction: str
    change_percentage: float
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class ThreatForecastingEngineCampaignPrediction:
    record_id: str
    tenant_id: str
    prediction_id: str
    actor_group: str
    predicted_date: str
    confidence_level: float
    created_at: datetime = field(default_factory=datetime.utcnow)
