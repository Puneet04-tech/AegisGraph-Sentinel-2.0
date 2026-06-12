"""
Security Digital Twin Models.

Models for enterprise security digital twin platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class SimulationType(str, Enum):
    """Simulation types."""
    THREAT = "threat"
    FRAUD = "fraud"
    ATTACK_PATH = "attack_path"
    COMPLIANCE = "compliance"
    SCENARIO = "scenario"


class AssetType(str, Enum):
    """Asset types in digital twin."""
    ENDPOINT = "endpoint"
    SERVER = "server"
    NETWORK = "network"
    APPLICATION = "application"
    USER = "user"
    DATA = "data"


class RiskLevel(str, Enum):
    """Risk levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SimulationStatus(str, Enum):
    """Simulation status."""
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class DigitalTwinAsset:
    """Asset in the digital twin."""
    asset_id: str
    asset_type: AssetType
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    connections: List[str] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class SimulationScenario:
    """Simulation scenario."""
    scenario_id: str
    name: str
    simulation_type: SimulationType
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    assets_involved: List[str] = field(default_factory=list)
    status: SimulationStatus = SimulationStatus.PLANNED


@dataclass
class ThreatSimulation:
    """Threat simulation result."""
    simulation_id: str
    scenario_id: str
    threat_type: str
    initial_conditions: Dict[str, Any]
    attack_steps: List[Dict[str, Any]] = field(default_factory=list)
    success_probability: float = 0.0
    impact_score: float = 0.0
    mitigation_recommendations: List[str] = field(default_factory=list)
    executed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class FraudSimulation:
    """Fraud simulation result."""
    simulation_id: str
    scenario_id: str
    fraud_type: str
    fraud_pattern: str
    accounts_involved: List[str] = field(default_factory=list)
    financial_impact: float = 0.0
    detection_likelihood: float = 0.0
    prevention_effectiveness: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    executed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AttackPath:
    """Attack path analysis."""
    path_id: str
    source_asset: str
    target_asset: str
    attack_steps: List[Dict[str, Any]] = field(default_factory=list)
    overall_risk: float = 0.0
    mitigation_points: List[str] = field(default_factory=list)


@dataclass
class RiskForecast:
    """Risk forecast."""
    forecast_id: str
    metric_type: str
    current_value: float
    forecasted_value: float
    confidence: float = 0.8
    time_horizon_days: int = 30
    factors: List[str] = field(default_factory=list)
    calculated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ImpactAssessment:
    """Impact assessment result."""
    assessment_id: str
    scenario_id: str
    affected_assets: List[str] = field(default_factory=list)
    financial_impact: float = 0.0
    operational_impact: float = 0.0
    reputational_impact: float = 0.0
    overall_impact_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)


@dataclass
class AuditEvent:
    """Audit event."""
    event_id: str
    timestamp: datetime
    user_id: str
    action: str
    resource_type: str
    resource_id: str
    details: Dict[str, Any] = field(default_factory=dict)
    success: bool = True