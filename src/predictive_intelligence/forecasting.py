"""
Risk Forecasting Engine.

Forecasts future risk scores and trends for entities.
"""

import time
import threading
from datetime import datetime
from threading import Lock
from typing import Dict, List, Optional, Any, Tuple
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
    
    #: Hours of forward horizon each forecast period represents. Used to
    #: extrapolate the fitted trend, replacing the dimensionless multipliers
    #: that were previously applied to the current score directly.
    PERIOD_HOURS = {
        ForecastPeriod.HOUR_1: 1.0,
        ForecastPeriod.HOURS_6: 6.0,
        ForecastPeriod.DAY_1: 24.0,
        ForecastPeriod.DAYS_7: 168.0,
        ForecastPeriod.DAYS_30: 720.0,
    }

    #: Observations required before a trend is fitted. Below this the series
    #: cannot distinguish a trend from noise, and the forecast says so rather
    #: than inventing a direction.
    MIN_OBSERVATIONS = 3

    #: Absolute risk change per hour below which a trend is reported as STABLE.
    #: A slope smaller than this is indistinguishable from measurement noise.
    STABLE_SLOPE_PER_HOUR = 0.001

    #: Confidence reported when there is insufficient history to fit a trend.
    NO_HISTORY_CONFIDENCE = 0.2

    def __init__(self, store: Optional[PredictiveStore] = None):
        """Initialize the risk forecaster.

        Args:
            store: Optional predictive store
        """
        self._store = store or get_predictive_store()

    def _fit_trend(
        self,
        observations: List[Tuple[datetime, float]],
    ) -> Tuple[Optional[float], float, float]:
        """Least-squares fit of risk against time.

        Args:
            observations: (timestamp, risk) pairs, oldest first

        Returns:
            Tuple of (slope per hour, intercept at the latest observation, R²).
            Slope is None when the series is too short or spans no time, which
            the callers report as an absence of trend rather than as STABLE.
        """
        if len(observations) < self.MIN_OBSERVATIONS:
            return None, 0.0, 0.0

        latest = observations[-1][0]
        # Hours relative to the most recent observation, so the intercept is
        # the fitted value at "now" and extrapolation is a simple offset.
        xs = [(ts - latest).total_seconds() / 3600.0 for ts, _ in observations]
        ys = [risk for _, risk in observations]

        n = len(xs)
        mean_x = sum(xs) / n
        mean_y = sum(ys) / n

        variance_x = sum((x - mean_x) ** 2 for x in xs)
        if variance_x == 0:
            # Every observation shares a timestamp; no trend is derivable.
            return None, mean_y, 0.0

        covariance = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
        slope = covariance / variance_x
        intercept = mean_y + slope * (0.0 - mean_x)

        # R² quantifies how much of the movement the trend actually explains,
        # and becomes the basis for confidence instead of a random draw.
        total_ss = sum((y - mean_y) ** 2 for y in ys)
        if total_ss == 0:
            # A perfectly flat series is fully explained by a zero slope.
            r_squared = 1.0
        else:
            residual_ss = sum(
                (y - (intercept + slope * x)) ** 2 for x, y in zip(xs, ys)
            )
            r_squared = max(0.0, 1.0 - residual_ss / total_ss)

        return slope, intercept, r_squared

    def _confidence(
        self,
        observations: List[Tuple[datetime, float]],
        r_squared: float,
    ) -> float:
        """Confidence in a fitted trend.

        Rises with both the amount of history and how well the trend explains
        it. Confidence was previously `random.uniform(0.6, 0.85)`, so a forecast
        with no supporting history was reported as confidently as one fitted to
        a long, clean series.
        """
        if len(observations) < self.MIN_OBSERVATIONS:
            return self.NO_HISTORY_CONFIDENCE

        # Saturates at 30 observations; more of the same adds little.
        sample_support = min(len(observations), 30) / 30.0
        confidence = 0.25 + 0.35 * sample_support + 0.35 * r_squared
        return round(min(0.95, confidence), 2)

    def record_observation(
        self,
        entity_id: str,
        risk_score: float,
        observed_at: Optional[datetime] = None,
    ) -> None:
        """Record an observed risk score so future forecasts can use it.

        Callers scoring an entity should feed the result back here; a forecast
        is only as good as the series behind it.
        """
        self._store.record_risk_observation(entity_id, risk_score, observed_at)
    
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

        # The current observation is part of the entity's history, so it is
        # recorded before the fit rather than being treated as separate.
        self._store.record_risk_observation(entity_id, current_risk)
        observations = self._store.get_risk_observations(entity_id)

        horizon_hours = self.PERIOD_HOURS.get(period, 24.0)
        slope, intercept, r_squared = self._fit_trend(observations)

        # Extrapolate the fitted trend across the horizon. This previously read
        # `current_risk + current_risk * multiplier * random.uniform(0.5, 1.5)`,
        # which drew the movement at random and — because every term was
        # positive — could only ever forecast risk going up. An entity whose
        # risk was steadily falling was still forecast to rise.
        if slope is None:
            # No usable history: the best estimate of future risk is present
            # risk, stated with low confidence rather than a fabricated move.
            predicted_risk = current_risk
            volatility = 0.0
        else:
            predicted_risk = intercept + slope * horizon_hours
            # Residual spread around the fit, as an honest volatility estimate.
            volatility = round(self._residual_spread(observations, slope, intercept), 4)

        predicted_risk = round(max(0.0, min(1.0, predicted_risk)), 4)

        factors = self._build_factors(
            current_risk, predicted_risk, slope, horizon_hours, len(observations)
        )

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
            confidence=self._confidence(observations, r_squared),
            factors=factors,
            recommendations=recommendations,
            metadata={
                "horizon_hours": horizon_hours,
                "volatility": volatility,
                "slope_per_hour": round(slope, 6) if slope is not None else None,
                "r_squared": round(r_squared, 4),
                "observation_count": len(observations),
            },
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
        self._store.record_risk_observation(entity_id, current_risk)
        observations = self._store.get_risk_observations(entity_id)

        slope, intercept, r_squared = self._fit_trend(observations)

        # Direction now follows the fitted slope. It was previously chosen by
        # `random.random()` against fixed 0.3/0.7 cut-offs, so neither the
        # entity nor its risk score influenced the trend at all: the same
        # entity was reported DECREASING on one call and INCREASING on the next.
        if slope is None:
            trend = "UNKNOWN"
            predicted_risk = current_risk
            time_to_peak = None
        elif abs(slope) < self.STABLE_SLOPE_PER_HOUR:
            trend = "STABLE"
            predicted_risk = current_risk
            time_to_peak = None
        elif slope < 0:
            trend = "DECREASING"
            # Projected one day ahead, floored at zero.
            predicted_risk = max(0.0, intercept + slope * 24.0)
            time_to_peak = None
        else:
            trend = "INCREASING"
            predicted_risk = min(1.0, intercept + slope * 24.0)
            time_to_peak = self._time_to_peak(intercept, slope)

        forecast = RiskForecast(
            entity_id=entity_id,
            current_risk=current_risk,
            predicted_risk=round(max(0.0, min(1.0, predicted_risk)), 4),
            risk_trend=trend,
            time_to_peak=time_to_peak,
            confidence=self._confidence(observations, r_squared),
        )
        
        # Store forecast
        self._store.store_risk_forecast(forecast)
        
        return forecast
    
    def _residual_spread(
        self,
        observations: List[Tuple[datetime, float]],
        slope: float,
        intercept: float,
    ) -> float:
        """Root-mean-square residual around the fitted trend.

        Reported as `volatility`, which was previously `random.uniform(0.05,
        0.15)` and so described nothing about the entity.
        """
        if len(observations) < self.MIN_OBSERVATIONS:
            return 0.0

        latest = observations[-1][0]
        residuals = [
            risk - (intercept + slope * ((ts - latest).total_seconds() / 3600.0))
            for ts, risk in observations
        ]
        mean_square = sum(r * r for r in residuals) / len(residuals)
        return mean_square ** 0.5

    def _time_to_peak(self, intercept: float, slope: float) -> Optional[str]:
        """Hours until a rising trend reaches maximum risk.

        Derived from the fitted slope. This was `f"{random.randint(1, 14)} days"`,
        an interval bearing no relation to how fast the entity's risk was
        actually moving.
        """
        if slope <= 0:
            return None

        remaining = 1.0 - intercept
        if remaining <= 0:
            return "already at peak"

        hours = remaining / slope
        if hours < 1:
            return "under 1 hour"
        if hours < 48:
            return f"{round(hours)} hours"
        return f"{round(hours / 24)} days"

    def _build_factors(
        self,
        current_risk: float,
        predicted_risk: float,
        slope: Optional[float],
        horizon_hours: float,
        observation_count: int,
    ) -> List[Dict[str, Any]]:
        """Describe what drove the forecast.

        The two supporting factors previously carried `random.uniform`
        contributions and `random.choice` directions, so the explanation
        attached to a forecast was unrelated to the forecast itself.
        """
        movement = predicted_risk - current_risk

        if slope is None:
            return [
                {
                    "factor": "insufficient_history",
                    "contribution": 0.0,
                    "direction": "UNKNOWN",
                    "detail": (
                        f"{observation_count} observation(s) recorded; at least "
                        f"{self.MIN_OBSERVATIONS} are needed to fit a trend"
                    ),
                }
            ]

        if movement > 0:
            direction = "INCREASING"
        elif movement < 0:
            direction = "DECREASING"
        else:
            direction = "STABLE"

        return [
            {
                "factor": "historical_risk_trend",
                "contribution": round(movement, 4),
                "direction": direction,
                "detail": (
                    f"Fitted slope {slope:+.6f}/hour over {observation_count} "
                    f"observations, projected {horizon_hours:.0f}h ahead"
                ),
            },
            {
                "factor": "current_risk_level",
                "contribution": round(current_risk, 4),
                "direction": "STABLE",
                "detail": "Latest observed risk score for the entity",
            },
        ]

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
_risk_forecaster_lock = Lock()


def get_risk_forecaster(store: Optional[PredictiveStore] = None) -> RiskForecaster:
    """Get or create the singleton RiskForecaster instance."""
    global _risk_forecaster
    
    with _risk_forecaster_lock:
        if _risk_forecaster is None:
            _risk_forecaster = RiskForecaster(store=store)
        return _risk_forecaster