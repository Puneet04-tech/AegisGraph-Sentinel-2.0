"""
Predictive Intelligence Module for AegisGraph Sentinel 2.0

Production-grade predictive intelligence subsystem capable of:
- Forecasting fraud risk before it occurs
- Simulating attack scenarios
- Predicting fraud campaign growth
- Forecasting attack paths
- Generating proactive prevention recommendations

Exports:
    SimulationScenario: Fraud simulation scenario model
    ForecastResult: Risk forecast result model
    CampaignPrediction: Campaign prediction model
    AttackPathPrediction: Attack path prediction model
    RiskForecast: Risk forecast model
    PreventiveRecommendation: Prevention recommendation model
    PredictiveStore: Storage for simulations and forecasts
    FraudSimulator: Fraud simulation engine
    RiskForecaster: Risk forecasting engine
    CampaignPredictor: Campaign prediction engine
    AttackPathPredictor: Attack path prediction engine
    RecommendationEngine: Prevention recommendation engine
"""

from .models import (
    SimulationScenario,
    SimulationType,
    SimulationStatus,
    SimulationResult,
    ForecastResult,
    ForecastPeriod,
    CampaignPrediction,
    CampaignStatus,
    AttackPathPrediction,
    RiskForecast,
    PreventiveRecommendation,
    RecommendationPriority,
    RecommendationType,
)
from .store import PredictiveStore, get_predictive_store
from .simulator import FraudSimulator, get_fraud_simulator
from .forecasting import RiskForecaster, get_risk_forecaster
from .campaign_predictor import CampaignPredictor, get_campaign_predictor
from .attack_predictor import AttackPathPredictor, get_attack_path_predictor
from .scenario_builder import ScenarioBuilder, get_scenario_builder
from .recommendation_engine import RecommendationEngine, get_recommendation_engine

__all__ = [
    # Models
    "SimulationScenario",
    "SimulationType",
    "SimulationStatus",
    "SimulationResult",
    "ForecastResult",
    "ForecastPeriod",
    "CampaignPrediction",
    "CampaignStatus",
    "AttackPathPrediction",
    "RiskForecast",
    "PreventiveRecommendation",
    "RecommendationPriority",
    "RecommendationType",
    # Store
    "PredictiveStore",
    "get_predictive_store",
    # Engines
    "FraudSimulator",
    "get_fraud_simulator",
    "RiskForecaster",
    "get_risk_forecaster",
    "CampaignPredictor",
    "get_campaign_predictor",
    "AttackPathPredictor",
    "get_attack_path_predictor",
    "ScenarioBuilder",
    "get_scenario_builder",
    "RecommendationEngine",
    "get_recommendation_engine",
]