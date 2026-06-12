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


# =============================================================================
# Global Fraud Prediction & Economic Impact Intelligence (Phase 52)
# =============================================================================

class ThreatCategory(str, Enum):
    """Categories of fraud threats."""
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    APPLICATION_FRAUD = "APPLICATION_FRAUD"
    CARD_FRAUD = "CARD_FRAUD"
    MULE_ACCOUNTS = "MULE_ACCOUNTS"
    SYNTHETIC_IDENTITY = "SYNTHETIC_IDENTITY"
    MONEY_LAUNDERING = "MONEY_LAUNDERING"
    AUTHORIZED_PUSH_PAYMENT = "AUTHORIZED_PUSH_PAYMENT"
    IDENTITY_THEFT = "IDENTITY_THEFT"


class IndustrySector(str, Enum):
    """Industry sectors for risk analysis."""
    BANKING = "BANKING"
    INSURANCE = "INSURANCE"
    RETAIL = "RETAIL"
    HEALTHCARE = "HEALTHCARE"
    TELECOM = "TELECOM"
    GAMING = "GAMING"
    CRYPTOCURRENCY = "CRYPTOCURRENCY"
    ECOMMERCE = "ECOMMERCE"
    PAYMENTS = "PAYMENTS"


class GeographicRegion(str, Enum):
    """Geographic regions for risk analysis."""
    NORTH_AMERICA = "NORTH_AMERICA"
    EUROPE = "EUROPE"
    ASIA_PACIFIC = "ASIA_PACIFIC"
    LATIN_AMERICA = "LATIN_AMERICA"
    MIDDLE_EAST = "MIDDLE_EAST"
    AFRICA = "AFRICA"
    GLOBAL = "GLOBAL"


class PredictionConfidence(str, Enum):
    """Prediction confidence levels."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class FraudPrediction:
    """Fraud prediction model.
    
    Attributes:
        prediction_id: Unique identifier
        entity_id: Entity being predicted
        threat_category: Category of predicted fraud
        probability: Probability of fraud occurrence (0-1)
        confidence: Confidence level in prediction
        predicted_time_window: Time window for predicted fraud
        risk_factors: Contributing risk factors
        recommended_actions: Actions to prevent fraud
        timestamp: When prediction was generated
    """
    prediction_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str = ""
    threat_category: ThreatCategory = ThreatCategory.ACCOUNT_TAKEOVER
    probability: float = 0.0
    confidence: PredictionConfidence = PredictionConfidence.MEDIUM
    predicted_time_window_start: Optional[datetime] = None
    predicted_time_window_end: Optional[datetime] = None
    risk_factors: List[Dict[str, Any]] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    historical_similarity_score: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "prediction_id": self.prediction_id,
            "entity_id": self.entity_id,
            "threat_category": self.threat_category.value,
            "probability": self.probability,
            "confidence": self.confidence.value,
            "predicted_time_window_start": self.predicted_time_window_start.isoformat() if self.predicted_time_window_start else None,
            "predicted_time_window_end": self.predicted_time_window_end.isoformat() if self.predicted_time_window_end else None,
            "risk_factors": self.risk_factors,
            "recommended_actions": self.recommended_actions,
            "historical_similarity_score": self.historical_similarity_score,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class EconomicImpact:
    """Economic impact assessment.
    
    Attributes:
        impact_id: Unique identifier
        threat_type: Type of threat
        estimated_financial_impact: Estimated financial loss
        affected_transactions: Number of affected transactions
        affected_entities: Number of affected entities
        recovery_cost: Estimated recovery cost
        operational_impact: Operational disruption score
        reputational_impact: Reputational damage score
        timeline: Impact timeline
        regional_scope: Geographic scope of impact
    """
    impact_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    threat_type: str = ""
    estimated_financial_impact: float = 0.0
    currency: str = "USD"
    affected_transactions: int = 0
    affected_entities: int = 0
    recovery_cost: float = 0.0
    operational_impact: float = 0.0  # 0-1 scale
    reputational_impact: float = 0.0  # 0-1 scale
    impact_timeline: Dict[str, Any] = field(default_factory=dict)
    regional_scope: List[GeographicRegion] = field(default_factory=list)
    industry_scope: List[IndustrySector] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "impact_id": self.impact_id,
            "threat_type": self.threat_type,
            "estimated_financial_impact": self.estimated_financial_impact,
            "currency": self.currency,
            "affected_transactions": self.affected_transactions,
            "affected_entities": self.affected_entities,
            "recovery_cost": self.recovery_cost,
            "operational_impact": self.operational_impact,
            "reputational_impact": self.reputational_impact,
            "impact_timeline": self.impact_timeline,
            "regional_scope": [r.value for r in self.regional_scope],
            "industry_scope": [s.value for s in self.industry_scope],
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class ThreatTrend:
    """Threat trend analysis.
    
    Attributes:
        trend_id: Unique identifier
        threat_category: Category of threat
        trend_direction: Trend direction (INCREASING, DECREASING, STABLE)
        velocity: Rate of change
        seasonality: Seasonal patterns
        geographic_hotspots: Regions with high activity
        affected_industries: Industries affected
        forecast: Future trend prediction
    """
    trend_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    threat_category: ThreatCategory = ThreatCategory.ACCOUNT_TAKEOVER
    trend_direction: str = "STABLE"
    velocity: float = 0.0  # percentage change per period
    growth_rate: float = 0.0
    seasonality_patterns: Dict[str, float] = field(default_factory=dict)
    geographic_hotspots: List[Dict[str, Any]] = field(default_factory=list)
    affected_industries: List[IndustrySector] = field(default_factory=list)
    historical_data_points: int = 0
    forecast_7d: float = 0.0
    forecast_30d: float = 0.0
    confidence_interval_95: Dict[str, float] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "trend_id": self.trend_id,
            "threat_category": self.threat_category.value,
            "trend_direction": self.trend_direction,
            "velocity": self.velocity,
            "growth_rate": self.growth_rate,
            "seasonality_patterns": self.seasonality_patterns,
            "geographic_hotspots": self.geographic_hotspots,
            "affected_industries": [s.value for s in self.affected_industries],
            "historical_data_points": self.historical_data_points,
            "forecast_7d": self.forecast_7d,
            "forecast_30d": self.forecast_30d,
            "confidence_interval_95": self.confidence_interval_95,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class AttackPrediction:
    """Attack pattern prediction.
    
    Attributes:
        prediction_id: Unique identifier
        attack_type: Type of attack
        predicted_timing: When attack is likely to occur
        predicted_scale: Expected scale of attack
        target_profiles: Likely target profiles
        attack_vector: Likely attack vector
        success_probability: Probability of attack success
        potential_damage: Potential damage estimate
    """
    prediction_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    attack_type: str = ""
    predicted_timing: Optional[datetime] = None
    predicted_timing_confidence: float = 0.5
    predicted_scale: str = "MEDIUM"  # SMALL, MEDIUM, LARGE, MASSIVE
    target_profiles: List[Dict[str, Any]] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    success_probability: float = 0.0
    potential_damage_min: float = 0.0
    potential_damage_max: float = 0.0
    recommended_mitigations: List[str] = field(default_factory=list)
    related_campaign_ids: List[str] = field(default_factory=list)
    confidence: PredictionConfidence = PredictionConfidence.MEDIUM
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "prediction_id": self.prediction_id,
            "attack_type": self.attack_type,
            "predicted_timing": self.predicted_timing.isoformat() if self.predicted_timing else None,
            "predicted_timing_confidence": self.predicted_timing_confidence,
            "predicted_scale": self.predicted_scale,
            "target_profiles": self.target_profiles,
            "attack_vectors": self.attack_vectors,
            "success_probability": self.success_probability,
            "potential_damage_min": self.potential_damage_min,
            "potential_damage_max": self.potential_damage_max,
            "recommended_mitigations": self.recommended_mitigations,
            "related_campaign_ids": self.related_campaign_ids,
            "confidence": self.confidence.value,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class IndustryRisk:
    """Industry-specific risk assessment.
    
    Attributes:
        risk_id: Unique identifier
        industry: Industry sector
        risk_score: Overall risk score (0-100)
        risk_factors: Contributing risk factors
        emerging_threats: Emerging threats for the industry
        benchmark_comparison: Comparison to industry benchmarks
        recommended_posture: Recommended defensive posture
    """
    risk_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    industry: IndustrySector = IndustrySector.BANKING
    risk_score: float = 50.0
    risk_factors: List[Dict[str, Any]] = field(default_factory=list)
    emerging_threats: List[str] = field(default_factory=list)
    threat_breakdown: Dict[str, float] = field(default_factory=dict)
    benchmark_score: float = 50.0
    percentile_rank: float = 50.0
    historical_trend: List[float] = field(default_factory=list)
    recommended_posture: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "risk_id": self.risk_id,
            "industry": self.industry.value,
            "risk_score": self.risk_score,
            "risk_factors": self.risk_factors,
            "emerging_threats": self.emerging_threats,
            "threat_breakdown": self.threat_breakdown,
            "benchmark_score": self.benchmark_score,
            "percentile_rank": self.percentile_rank,
            "historical_trend": self.historical_trend,
            "recommended_posture": self.recommended_posture,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class GeographicRisk:
    """Geographic risk assessment.
    
    Attributes:
        risk_id: Unique identifier
        region: Geographic region
        risk_score: Regional risk score (0-100)
        fraud_density: Fraud incidents per capita
        threat_actors: Active threat actors in region
        regulatory_environment: Regulatory risk level
        economic_factors: Economic risk factors
    """
    risk_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    region: GeographicRegion = GeographicRegion.GLOBAL
    country_codes: List[str] = field(default_factory=list)
    risk_score: float = 50.0
    fraud_density: float = 0.0  # incidents per 100,000 population
    threat_actor_activity: Dict[str, float] = field(default_factory=dict)
    regulatory_environment_score: float = 50.0
    economic_risk_factors: Dict[str, float] = field(default_factory=dict)
    historical_incident_count: int = 0
    trend_direction: str = "STABLE"
    risk_contributors: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "risk_id": self.risk_id,
            "region": self.region.value,
            "country_codes": self.country_codes,
            "risk_score": self.risk_score,
            "fraud_density": self.fraud_density,
            "threat_actor_activity": self.threat_actor_activity,
            "regulatory_environment_score": self.regulatory_environment_score,
            "economic_risk_factors": self.economic_risk_factors,
            "historical_incident_count": self.historical_incident_count,
            "trend_direction": self.trend_direction,
            "risk_contributors": self.risk_contributors,
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