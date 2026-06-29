from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class SecurityDigitalTwinDigitalTwinState:
    record_id: str
    tenant_id: str
    state_id: str
    entity_id: str
    posture_score: float
    anomaly_detected: bool
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class SecurityDigitalTwinRiskVisualizationNode:
    record_id: str
    tenant_id: str
    node_id: str
    asset_name: str
    risk_level: str
    x_y_coordinates: List[float]
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class SecurityDigitalTwinForecastingScenario:
    record_id: str
    tenant_id: str
    scenario_id: str
    predicted_impact: str
    forecasting_accuracy: float
    is_critical: bool
    created_at: datetime = field(default_factory=datetime.utcnow)
