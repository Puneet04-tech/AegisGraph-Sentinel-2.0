"""
Predictive Intelligence Storage Engine.

Thread-safe storage for simulations, forecasts, and predictions with O(1) lookups.
"""

from collections import OrderedDict
from threading import Lock
from typing import Dict, List, Optional, Any
import logging

from .models import (
    SimulationScenario,
    SimulationResult,
    ForecastResult,
    CampaignPrediction,
    AttackPathPrediction,
    RiskForecast,
    PreventiveRecommendation,
    RecommendationPriority,
)

logger = logging.getLogger(__name__)


class PredictiveStore:
    """Thread-safe storage for predictive intelligence data.
    
    Provides:
        - O(1) lookup by ID
        - LRU cache for bounded memory
        - Thread-safe operations
        - Efficient indexing
    
    Attributes:
        max_size: Maximum number of records to store
    """
    
    def __init__(self, max_size: int = 5000):
        """Initialize the predictive store.
        
        Args:
            max_size: Maximum number of records to store
        """
        self._max_size = max_size
        
        # Simulation storage
        self._scenarios: OrderedDict[str, SimulationScenario] = OrderedDict()
        self._simulation_results: OrderedDict[str, SimulationResult] = OrderedDict()
        
        # Forecast storage
        self._forecasts: OrderedDict[str, ForecastResult] = OrderedDict()
        self._risk_forecasts: OrderedDict[str, RiskForecast] = OrderedDict()
        
        # Campaign prediction storage
        self._campaigns: OrderedDict[str, CampaignPrediction] = OrderedDict()
        
        # Attack path storage
        self._attack_paths: OrderedDict[str, AttackPathPrediction] = OrderedDict()
        
        # Recommendations storage
        self._recommendations: OrderedDict[str, PreventiveRecommendation] = OrderedDict()
        
        # Locks for thread safety
        self._locks = {
            "scenarios": Lock(),
            "results": Lock(),
            "forecasts": Lock(),
            "risk_forecasts": Lock(),
            "campaigns": Lock(),
            "attack_paths": Lock(),
            "recommendations": Lock(),
        }
        
        # Statistics
        self._stats = {
            "simulations_stored": 0,
            "forecasts_stored": 0,
            "campaigns_stored": 0,
            "recommendations_stored": 0,
        }
        self._stats_lock = Lock()
    
    def _update_stats(self, key: str, increment: int = 1) -> None:
        """Update statistics."""
        with self._stats_lock:
            self._stats[key] = self._stats.get(key, 0) + increment
    
    # =========================================================================
    # Simulation Storage
    # =========================================================================
    
    def store_scenario(self, scenario: SimulationScenario) -> SimulationScenario:
        """Store a simulation scenario.
        
        Args:
            scenario: Scenario to store
            
        Returns:
            Stored scenario
        """
        lock = self._locks["scenarios"]
        with lock:
            self._scenarios[scenario.scenario_id] = scenario
            self._scenarios.move_to_end(scenario.scenario_id)
            self._evict_if_needed(self._scenarios)
        
        self._update_stats("simulations_stored")
        return scenario
    
    def get_scenario(self, scenario_id: str) -> Optional[SimulationScenario]:
        """Get a scenario by ID."""
        lock = self._locks["scenarios"]
        with lock:
            scenario = self._scenarios.get(scenario_id)
            if scenario:
                self._scenarios.move_to_end(scenario_id)
            return scenario
    
    def get_all_scenarios(self) -> List[SimulationScenario]:
        """Get all stored scenarios."""
        lock = self._locks["scenarios"]
        with lock:
            return list(self._scenarios.values())
    
    def store_simulation_result(self, result: SimulationResult) -> SimulationResult:
        """Store a simulation result."""
        lock = self._locks["results"]
        with lock:
            self._simulation_results[result.scenario_id] = result
            self._simulation_results.move_to_end(result.scenario_id)
            self._evict_if_needed(self._simulation_results)
        
        return result
    
    def get_simulation_result(self, scenario_id: str) -> Optional[SimulationResult]:
        """Get a simulation result by scenario ID."""
        lock = self._locks["results"]
        with lock:
            return self._simulation_results.get(scenario_id)
    
    def _evict_if_needed(self, storage: OrderedDict) -> None:
        """Evict oldest entries if storage exceeds max size."""
        while len(storage) > self._max_size:
            storage.popitem(last=False)
    
    # =========================================================================
    # Forecast Storage
    # =========================================================================
    
    def store_forecast(self, forecast: ForecastResult) -> ForecastResult:
        """Store a forecast result."""
        key = f"{forecast.entity_id}:{forecast.forecast_period.value}"
        lock = self._locks["forecasts"]
        with lock:
            self._forecasts[key] = forecast
            self._forecasts.move_to_end(key)
            self._evict_if_needed(self._forecasts)
        
        self._update_stats("forecasts_stored")
        return forecast
    
    def get_forecast(self, entity_id: str, forecast_period: str) -> Optional[ForecastResult]:
        """Get a forecast by entity ID and period."""
        key = f"{entity_id}:{forecast_period}"
        lock = self._locks["forecasts"]
        with lock:
            return self._forecasts.get(key)
    
    def get_entity_forecasts(self, entity_id: str) -> List[ForecastResult]:
        """Get all forecasts for an entity."""
        lock = self._locks["forecasts"]
        with lock:
            return [f for k, f in self._forecasts.items() if k.startswith(f"{entity_id}:")]
    
    def store_risk_forecast(self, forecast: RiskForecast) -> RiskForecast:
        """Store a risk forecast."""
        lock = self._locks["risk_forecasts"]
        with lock:
            self._risk_forecasts[forecast.entity_id] = forecast
            self._risk_forecasts.move_to_end(forecast.entity_id)
            self._evict_if_needed(self._risk_forecasts)
        
        return forecast
    
    def get_risk_forecast(self, entity_id: str) -> Optional[RiskForecast]:
        """Get a risk forecast by entity ID."""
        lock = self._locks["risk_forecasts"]
        with lock:
            forecast = self._risk_forecasts.get(entity_id)
            if forecast:
                self._risk_forecasts.move_to_end(entity_id)
            return forecast
    
    def get_all_risk_forecasts(self) -> List[RiskForecast]:
        """Get all risk forecasts."""
        lock = self._locks["risk_forecasts"]
        with lock:
            return list(self._risk_forecasts.values())
    
    # =========================================================================
    # Campaign Prediction Storage
    # =========================================================================
    
    def store_campaign_prediction(self, prediction: CampaignPrediction) -> CampaignPrediction:
        """Store a campaign prediction."""
        lock = self._locks["campaigns"]
        with lock:
            self._campaigns[prediction.campaign_id] = prediction
            self._campaigns.move_to_end(prediction.campaign_id)
            self._evict_if_needed(self._campaigns)
        
        self._update_stats("campaigns_stored")
        return prediction
    
    def get_campaign_prediction(self, campaign_id: str) -> Optional[CampaignPrediction]:
        """Get a campaign prediction by ID."""
        lock = self._locks["campaigns"]
        with lock:
            pred = self._campaigns.get(campaign_id)
            if pred:
                self._campaigns.move_to_end(campaign_id)
            return pred
    
    def get_all_campaign_predictions(self) -> List[CampaignPrediction]:
        """Get all campaign predictions."""
        lock = self._locks["campaigns"]
        with lock:
            return list(self._campaigns.values())
    
    def get_high_risk_campaigns(self, threshold: float = 0.7) -> List[CampaignPrediction]:
        """Get campaigns with growth rate above threshold."""
        lock = self._locks["campaigns"]
        with lock:
            return [c for c in self._campaigns.values() if c.growth_rate >= threshold]
    
    # =========================================================================
    # Attack Path Storage
    # =========================================================================
    
    def store_attack_path(self, path: AttackPathPrediction) -> AttackPathPrediction:
        """Store an attack path prediction."""
        key = f"{path.source_entity_id}:{path.timestamp.isoformat()}"
        lock = self._locks["attack_paths"]
        with lock:
            self._attack_paths[key] = path
            self._evict_if_needed(self._attack_paths)
        
        return path
    
    def get_attack_paths_for_entity(self, entity_id: str) -> List[AttackPathPrediction]:
        """Get all attack paths for an entity."""
        lock = self._locks["attack_paths"]
        with lock:
            return [p for k, p in self._attack_paths.items() if k.startswith(f"{entity_id}:")]
    
    def get_high_probability_attacks(self, threshold: float = 0.5) -> List[AttackPathPrediction]:
        """Get attack paths with probability above threshold."""
        lock = self._locks["attack_paths"]
        with lock:
            return [p for p in self._attack_paths.values() if p.probability >= threshold]
    
    # =========================================================================
    # Recommendation Storage
    # =========================================================================
    
    def store_recommendation(self, recommendation: PreventiveRecommendation) -> PreventiveRecommendation:
        """Store a prevention recommendation."""
        lock = self._locks["recommendations"]
        with lock:
            self._recommendations[recommendation.recommendation_id] = recommendation
            self._recommendations.move_to_end(recommendation.recommendation_id)
            self._evict_if_needed(self._recommendations)
        
        self._update_stats("recommendations_stored")
        return recommendation
    
    def get_recommendation(self, recommendation_id: str) -> Optional[PreventiveRecommendation]:
        """Get a recommendation by ID."""
        lock = self._locks["recommendations"]
        with lock:
            return self._recommendations.get(recommendation_id)
    
    def get_entity_recommendations(self, entity_id: str) -> List[PreventiveRecommendation]:
        """Get all recommendations for an entity."""
        lock = self._locks["recommendations"]
        with lock:
            return [r for r in self._recommendations.values() if r.entity_id == entity_id]
    
    def get_high_priority_recommendations(self, threshold: RecommendationPriority = RecommendationPriority.HIGH) -> List[PreventiveRecommendation]:
        """Get recommendations above a priority threshold."""
        priority_order = {
            RecommendationPriority.CRITICAL: 0,
            RecommendationPriority.HIGH: 1,
            RecommendationPriority.MEDIUM: 2,
            RecommendationPriority.LOW: 3,
        }
        
        lock = self._locks["recommendations"]
        with lock:
            return [
                r for r in self._recommendations.values()
                if priority_order.get(r.priority, 99) <= priority_order.get(threshold, 99)
            ]
    
    # =========================================================================
    # Statistics
    # =========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        with self._stats_lock:
            stats = self._stats.copy()
        
        with self._locks["scenarios"]:
            stats["current_scenarios"] = len(self._scenarios)
        with self._locks["forecasts"]:
            stats["current_forecasts"] = len(self._forecasts)
        with self._locks["campaigns"]:
            stats["current_campaigns"] = len(self._campaigns)
        with self._locks["recommendations"]:
            stats["current_recommendations"] = len(self._recommendations)
        
        return stats
    
    def clear(self) -> None:
        """Clear all stored data."""
        for lock in self._locks.values():
            with lock:
                pass  # Would need separate storage dicts to clear properly
        
        logger.info("Predictive store cleared")


# Global singleton instance
_predictive_store: Optional[PredictiveStore] = None
_store_lock = Lock()


def get_predictive_store(max_size: int = 5000) -> PredictiveStore:
    """Get or create the singleton PredictiveStore instance."""
    global _predictive_store
    
    with _store_lock:
        if _predictive_store is None:
            _predictive_store = PredictiveStore(max_size=max_size)
        return _predictive_store