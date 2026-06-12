"""
Threat Simulation Environment Models
Advanced threat simulation and evaluation.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class AttackType(Enum):
    """Types of simulated attacks."""
    PHISHING = "PHISHING"
    MALWARE = "MALWARE"
    RANSOMWARE = "RANSOMWARE"
    INSIDER_THREAT = "INSIDER_THREAT"
    DDoS = "DDOS"
    SQL_INJECTION = "SQL_INJECTION"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    FRAUD_ATTACK = "FRAUD_ATTACK"


class ThreatLevel(Enum):
    """Threat levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


class SimulationRunStatus(Enum):
    """Simulation run status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass
class ThreatActor:
    """Simulated threat actor."""
    actor_id: str
    name: str
    sophistication: str
    motivation: str
    capabilities: List[str]
    targets: List[str]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "name": self.name,
            "sophistication": self.sophistication,
            "motivation": self.motivation,
            "capabilities": self.capabilities,
            "targets": self.targets,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class AttackScenario:
    """Attack scenario for simulation."""
    scenario_id: str
    name: str
    attack_type: AttackType
    description: str
    steps: List[Dict[str, Any]]
    prerequisites: List[str]
    expected_impact: Dict[str, Any]
    success_indicators: List[str]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "attack_type": self.attack_type.value,
            "description": self.description,
            "steps": self.steps,
            "prerequisites": self.prerequisites,
            "expected_impact": self.expected_impact,
            "success_indicators": self.success_indicators,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class SimulationRun:
    """A simulation run."""
    run_id: str
    scenario_id: str
    actor_id: str
    status: SimulationRunStatus = SimulationRunStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    events: List[Dict[str, Any]] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "actor_id": self.actor_id,
            "status": self.status.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "events": self.events,
            "results": self.results,
            "metrics": self.metrics,
        }


@dataclass
class ThreatEvaluation:
    """Threat evaluation result."""
    evaluation_id: str
    run_id: str
    threat_score: float
    detection_rate: float
    response_time: float
    effectiveness: float
    recommendations: List[str]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "evaluation_id": self.evaluation_id,
            "run_id": self.run_id,
            "threat_score": self.threat_score,
            "detection_rate": self.detection_rate,
            "response_time": self.response_time,
            "effectiveness": self.effectiveness,
            "recommendations": self.recommendations,
            "created_at": self.created_at.isoformat(),
        }