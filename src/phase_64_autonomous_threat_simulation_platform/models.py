from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class ThreatSimulationPlatformThreatScenario:
    record_id: str
    tenant_id: str
    scenario_id: str
    scenario_type: str
    steps: List[str]
    target_assets: List[str]
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class ThreatSimulationPlatformFraudSimulation:
    record_id: str
    tenant_id: str
    simulation_id: str
    campaign_type: str
    detection_rate: float
    status: str
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class ThreatSimulationPlatformResilienceMetrics:
    record_id: str
    tenant_id: str
    metrics_id: str
    scenario_id: str
    breach_probability: float
    mitigation_score: float
    created_at: datetime = field(default_factory=datetime.utcnow)
