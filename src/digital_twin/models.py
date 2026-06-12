"""
Digital Twin Platform Models
Enterprise ecosystem digital twin representation.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class TwinType(Enum):
    """Types of digital twins."""
    FRAUD_ECOSYSTEM = "FRAUD_ECOSYSTEM"
    CYBER_NETWORK = "CYBER_NETWORK"
    COMPLIANCE_ENVIRONMENT = "COMPLIANCE_ENVIRONMENT"
    INVESTIGATION_DOMAIN = "INVESTIGATION_DOMAIN"
    AML_NETWORK = "AML_NETWORK"
    THREAT_LANDSCAPE = "THREAT_LANDSCAPE"


class SimulationStatus(Enum):
    """Simulation status."""
    READY = "READY"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScenarioType(Enum):
    """Types of scenarios."""
    ATTACK_SIMULATION = "ATTACK_SIMULATION"
    FRAUD_SCENARIO = "FRAUD_SCENARIO"
    COMPLIANCE_TEST = "COMPLIANCE_TEST"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    RESPONSE_DRILL = "RESPONSE_DRILL"


@dataclass
class DigitalTwin:
    """A digital twin representation."""
    twin_id: str
    name: str
    twin_type: TwinType
    entities: List[Dict[str, Any]] = field(default_factory=list)
    relationships: List[Dict[str, Any]] = field(default_factory=list)
    metrics: Dict[str, float] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "twin_id": self.twin_id,
            "name": self.name,
            "twin_type": self.twin_type.value,
            "entities": self.entities,
            "relationships": self.relationships,
            "metrics": self.metrics,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class Simulation:
    """A simulation run."""
    simulation_id: str
    twin_id: str
    scenario_type: ScenarioType
    status: SimulationStatus = SimulationStatus.READY
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    results: Dict[str, Any] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "simulation_id": self.simulation_id,
            "twin_id": self.twin_id,
            "scenario_type": self.scenario_type.value,
            "status": self.status.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "results": self.results,
            "parameters": self.parameters,
            "events": self.events,
        }


@dataclass
class Scenario:
    """A scenario for simulation."""
    scenario_id: str
    name: str
    description: str
    scenario_type: ScenarioType
    twin_type: TwinType
    steps: List[Dict[str, Any]]
    expected_outcomes: List[str]
    success_criteria: Dict[str, Any]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "description": self.description,
            "scenario_type": self.scenario_type.value,
            "twin_type": self.twin_type.value,
            "steps": self.steps,
            "expected_outcomes": self.expected_outcomes,
            "success_criteria": self.success_criteria,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class RiskAnalysis:
    """Risk analysis result."""
    analysis_id: str
    twin_id: str
    risk_score: float
    affected_entities: List[str]
    risk_factors: List[Dict[str, Any]]
    mitigation_actions: List[str]
    recommendations: List[str]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "twin_id": self.twin_id,
            "risk_score": self.risk_score,
            "affected_entities": self.affected_entities,
            "risk_factors": self.risk_factors,
            "mitigation_actions": self.mitigation_actions,
            "recommendations": self.recommendations,
            "created_at": self.created_at.isoformat(),
        }