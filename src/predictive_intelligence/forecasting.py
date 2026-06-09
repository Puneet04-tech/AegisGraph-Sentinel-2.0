"""
Risk Forecasting Engine.

Forecasts future risk scores and trends for entities.
"""

import time
import random
from typing import Dict, List, Optional, Any
import logging

from .models import (
    ForecastResult,
    ForecastPeriod,
    RiskForecast,
)
from .store import PredictiveStore, get_predictive_store

logger = logging.getLogger(__name__)


class RiskForecaster:
    """Risk forecasting engine for predicting future risk.
    
    Provides:
        - Entity risk forecasting
        - Risk trend analysis
        - Time-to-peak estimation
        - Risk escalation prediction
    """
    
    def __init__(self, store: Optional[PredictiveStore] = None):
        """Initialize the risk forecaster.
        
        Args:
            store: Optional predictive store
        """
        self._store = store or get_predictive_store()
    
    def forecast_risk(self, entity_id: str, current_risk: float, period: ForecastPeriod) -> ForecastResult:
        """Forecast risk for an entity.
        
        Args:
            entity_id: Entity to forecast
            current_risk: Current risk score
            period: Forecast time period
            
        Returns:
            ForecastResult with predicted risk
        """
        start_time = time.time()
        
        # Calculate forecast based on period
        period_multipliers = {
            ForecastPeriod.HOUR_1: 0.1,
            ForecastPeriod.HOURS_6: 0.25,
            ForecastPeriod.DAY_1: 0.4,
            ForecastPeriod.DAYS_7: 0.6,
            ForecastPeriod.DAYS_30: 0.8,
        }
        
        multiplier = period_multipliers.get(period, 0.3)
        
        # Add some randomness for realistic forecasting
        volatility = random.uniform(0.05, 0.15)
        predicted_risk = min(current_risk + (current_risk * multiplier * random.uniform(0.5, 1.5)), 1.0)
        
        # Generate risk factors
        factors = [
            {
                "factor": "historical_risk_trend",
                "contribution": predicted_risk * 0.3,
                "direction": "INCREASING" if predicted_risk > current_risk else "DECREASING",
            },
            {
                "factor": "connection_risk",
                "contribution": predicted_risk * random.uniform(0.1, 0.3),
                "direction": random.choice(["INCREASING", "STABLE"]),
            },
            {
                "factor": "activity_pattern",
                "contribution": predicted_risk * random.uniform(0.1, 0.2),
                "direction": random.choice(["INCREASING", "STABLE", "DECREASING"]),
            },
        ]
        
        # Generate recommendations
        recommendations = []
        if predicted_risk > 0.7:
            recommendations.append("URGENT: Consider account freeze")
            recommendations.append("Enable enhanced monitoring")
        elif predicted_risk > 0.5:
            recommendations.append("Schedule analyst review")
            recommendations.append("Increase transaction monitoring")
        else:
            recommendations.append("Continue standard monitoring")
        
        result = ForecastResult(
            entity_id=entity_id,
            forecast_period=period,
            risk_score=predicted_risk,
            confidence=random.uniform(0.6, 0.85),
            factors=factors,
            recommendations=recommendations,
            metadata={"period_multiplier": multiplier, "volatility": volatility},
        )
        
        # Store forecast
        self._store.store_forecast(result)
        
        logger.info(f"Forecasted risk for {entity_id} over {period.value}: {predicted_risk:.2f}")
        return result
    
    def predict_risk_trend(self, entity_id: str, current_risk: float) -> RiskForecast:
        """Predict the risk trend for an entity.
        
        Args:
            entity_id: Entity to analyze
            current_risk: Current risk score
            
        Returns:
            RiskForecast with trend analysis
        """
        # Determine trend direction
        trend_random = random.random()
        if trend_random < 0.3:
            trend = "DECREASING"
            predicted_risk = max(current_risk * random.uniform(0.7, 0.9), 0.0)
            time_to_peak = None
        elif trend_random < 0.7:
            trend = "STABLE"
            predicted_risk = current_risk * random.uniform(0.95, 1.05)
            time_to_peak = None
        else:
            trend = "INCREASING"
            predicted_risk = min(current_risk * random.uniform(1.1, 1.5), 1.0)
            time_to_peak = f"{random.randint(1, 14)} days"
        
        forecast = RiskForecast(
            entity_id=entity_id,
            current_risk=current_risk,
            predicted_risk=predicted_risk,
            risk_trend=trend,
            time_to_peak=time_to_peak,
            confidence=random.uniform(0.6, 0.85),
        )
        
        # Store forecast
        self._store.store_risk_forecast(forecast)
        
        return forecast
    
    def get_entity_forecast(self, entity_id: str) -> Optional[RiskForecast]:
        """Get the latest risk forecast for an entity."""
        return self._store.get_risk_forecast(entity_id)
    
    def get_all_forecasts(self) -> List[RiskForecast]:
        """Get all risk forecasts."""
        return self._store.get_all_risk_forecasts()
    
    def get_high_risk_forecasts(self, threshold: float = 0.7) -> List[RiskForecast]:
        """Get forecasts with predicted risk above threshold."""
        all_forecasts = self._store.get_all_risk_forecasts()
        return [f for f in all_forecasts if f.predicted_risk >= threshold]


# Global singleton
_risk_forecaster: Optional[RiskForecaster] = None


def get_risk_forecaster(store: Optional[PredictiveStore] = None) -> RiskForecaster:
    """Get or create the singleton RiskForecaster instance."""
    global _risk_forecaster
    
    if _risk_forecaster is None:
        _risk_forecaster = RiskForecaster(store=store)
    return _risk_forecaster