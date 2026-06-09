"""
Data models for Predictive Intelligence Engine.

Core models:
    SimulationScenario: Fraud simulation scenario
    SimulationResult: Result of a fraud simulation
    ForecastResult: Risk forecast result
    CampaignPrediction: Campaign growth prediction
    AttackPathPrediction: Attack path forecast
    RiskForecast: Entity risk forecast
    PreventiveRecommendation: Prevention recommendation
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, Any
import uuid


class SimulationType(str, Enum):
    """Types of fraud simulations."""
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    FRAUD_RING_EXPANSION = "FRAUD_RING_EXPANSION"
    SYNTHETIC_IDENTITY = "SYNTHETIC_IDENTITY"
    WALLET_LAUNDERING = "WALLET_LAUNDERING"
    CAMPAIGN_SPREAD = "CAMPAIGN_SPREAD"
    MULE_ACCOUNT_CREATION = "MULE_ACCOUNT_CREATION"
    NETWORK_INFILTRATION = "NETWORK_INFILTRATION"


class SimulationStatus(str, Enum):
    """Status of a simulation."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ForecastPeriod(str, Enum):
    """Forecast time periods."""
    HOUR_1 = "HOUR_1"
    HOURS_6 = "HOURS_6"
    DAY_1 = "DAY_1"
    DAYS_7 = "DAYS_7"
    DAYS_30 = "DAYS_30"


class CampaignStatus(str, Enum):
    """Campaign status predictions."""
    EMERGING = "EMERGING"
    GROWING = "GROWING"
    PEAKED = "PEAKED"
    DECLINING = "DECLINING"
    DORMANT = "DORMANT"


class RecommendationPriority(str, Enum):
    """Priority levels for recommendations."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RecommendationType(str, Enum):
    """Types of prevention recommendations."""
    ACCOUNT_FREEZE = "ACCOUNT_FREEZE"
    ENHANCED_MONITORING = "ENHANCED_MONITORING"
    ANALYST_REVIEW = "ANALYST_REVIEW"
    ENTITY_BLOCK = "ENTITY_BLOCK"
    TRANSACTION_LIMIT = "TRANSACTION_LIMIT"
    DEVICE_RESTRICTION = "DEVICE_RESTRICTION"
    KYC_ENHANCEMENT = "KYC_ENHANCEMENT"
    ALERT_CREATION = "ALERT_CREATION"


@dataclass
class SimulationScenario:
    """Represents a fraud simulation scenario.
    
    Attributes:
        scenario_id: Unique identifier
        simulation_type: Type of fraud simulation
        source_entity_ids: Entities involved in simulation
        parameters: Simulation parameters
        status: Current simulation status
        created_at: When simulation was created
        created_by: Who created the simulation
    """
    scenario_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    simulation_type: SimulationType = SimulationType.ACCOUNT_TAKEOVER
    source_entity_ids: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: SimulationStatus = SimulationStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "system"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scenario_id": self.scenario_id,
            "simulation_type": self.simulation_type.value,
            "source_entity_ids": self.source_entity_ids,
            "parameters": self.parameters,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SimulationScenario":
        """Create from dictionary."""
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        else:
            created_at = datetime.now(timezone.utc)
        
        return cls(
            scenario_id=data.get("scenario_id", str(uuid.uuid4())),
            simulation_type=SimulationType(data.get("simulation_type", "ACCOUNT_TAKEOVER")),
            source_entity_ids=data.get("source_entity_ids", []),
            parameters=data.get("parameters", {}),
            status=SimulationStatus(data.get("status", "PENDING")),
            created_at=created_at,
            created_by=data.get("created_by", "system"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class SimulationResult:
    """Result of a fraud simulation.
    
    Attributes:
        scenario_id: Associated scenario ID
        predicted_outcomes: List of predicted outcomes
        risk_score: Simulated risk score
        affected_entities: Entities likely to be affected
        confidence: Confidence in simulation
        processing_time_ms: Time taken for simulation
        timestamp: When simulation completed
    """
    scenario_id: str
    predicted_outcomes: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    affected_entities: List[str] = field(default_factory=list)
    confidence: float = 0.5
    processing_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scenario_id": self.scenario_id,
            "predicted_outcomes": self.predicted_outcomes,
            "risk_score": self.risk_score,
            "affected_entities": self.affected_entities,
            "confidence": self.confidence,
            "processing_time_ms": self.processing_time_ms,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class ForecastResult:
    """Risk forecast result.
    
    Attributes:
        entity_id: Entity being forecasted
        forecast_period: Time period for forecast
        risk_score: Predicted risk score
        confidence: Confidence in forecast
        factors: Risk factors contributing to forecast
        recommendations: Suggested actions
        timestamp: When forecast was generated
    """
    entity_id: str
    forecast_period: ForecastPeriod
    risk_score: float = 0.0
    confidence: float = 0.5
    factors: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "entity_id": self.entity_id,
            "forecast_period": self.forecast_period.value,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "factors": self.factors,
            "recommendations": self.recommendations,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class CampaignPrediction:
    """Campaign growth prediction.
    
    Attributes:
        campaign_id: Identifier for the campaign
        campaign_name: Name of the campaign
        predicted_status: Predicted campaign status
        growth_rate: Predicted growth rate
        affected_entities: Entities likely to be affected
        peak_time: Predicted peak time
        confidence: Confidence in prediction
        timestamp: When prediction was generated
    """
    campaign_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    campaign_name: str = ""
    predicted_status: CampaignStatus = CampaignStatus.EMERGING
    growth_rate: float = 0.0
    affected_entities: List[str] = field(default_factory=list)
    peak_time: Optional[datetime] = None
    confidence: float = 0.5
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "campaign_id": self.campaign_id,
            "campaign_name": self.campaign_name,
            "predicted_status": self.predicted_status.value,
            "growth_rate": self.growth_rate,
            "affected_entities": self.affected_entities,
            "peak_time": self.peak_time.isoformat() if self.peak_time else None,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class AttackPathPrediction:
    """Attack path forecast.
    
    Attributes:
        source_entity_id: Starting entity
        predicted_path: List of entities in predicted path
        probability: Probability of attack succeeding
        estimated_damage: Estimated financial damage
        confidence: Confidence in prediction
        timestamp: When prediction was generated
    """
    source_entity_id: str
    predicted_path: List[str] = field(default_factory=list)
    probability: float = 0.0
    estimated_damage: float = 0.0
    confidence: float = 0.5
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source_entity_id": self.source_entity_id,
            "predicted_path": self.predicted_path,
            "probability": self.probability,
            "estimated_damage": self.estimated_damage,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class RiskForecast:
    """Entity risk forecast.
    
    Attributes:
        entity_id: Entity being forecasted
        current_risk: Current risk score
        predicted_risk: Predicted future risk
        risk_trend: Risk trend direction
        time_to_peak: Estimated time to peak risk
        confidence: Confidence in forecast
        timestamp: When forecast was generated
    """
    entity_id: str
    current_risk: float = 0.0
    predicted_risk: float = 0.0
    risk_trend: str = "STABLE"  # INCREASING, DECREASING, STABLE
    time_to_peak: Optional[str] = None
    confidence: float = 0.5
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "entity_id": self.entity_id,
            "current_risk": self.current_risk,
            "predicted_risk": self.predicted_risk,
            "risk_trend": self.risk_trend,
            "time_to_peak": self.time_to_peak,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class PreventiveRecommendation:
    """Prevention recommendation.
    
    Attributes:
        recommendation_id: Unique identifier
        entity_id: Target entity
        recommendation_type: Type of recommendation
        priority: Priority level
        description: Recommendation description
        expected_impact: Expected risk reduction
        timestamp: When recommendation was generated
    """
    recommendation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str = ""
    recommendation_type: RecommendationType = RecommendationType.ENHANCED_MONITORING
    priority: RecommendationPriority = RecommendationPriority.MEDIUM
    description: str = ""
    expected_impact: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "recommendation_id": self.recommendation_id,
            "entity_id": self.entity_id,
            "recommendation_type": self.recommendation_type.value,
            "priority": self.priority.value,
            "description": self.description,
            "expected_impact": self.expected_impact,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


# Import store and engines for singleton getters
from .store import PredictiveStore, get_predictive_store
from .simulator import FraudSimulator, get_fraud_simulator
from .forecasting import RiskForecaster, get_risk_forecaster
from .campaign_predictor import CampaignPredictor, get_campaign_predictor
from .attack_predictor import AttackPathPredictor, get_attack_path_predictor
from .scenario_builder import ScenarioBuilder, get_scenario_builder
from .recommendation_engine import RecommendationEngine, get_recommendation_engine