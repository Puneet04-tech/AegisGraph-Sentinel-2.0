"""
Global Threat Forecasting Platform Service
"""

from __future__ import annotations

from datetime import datetime, timezone  # noqa: F401
from typing import List, Optional

from .models import (
    ThreatForecast,
    CampaignPrediction,
    TrendAnalysis,
    EconomicImpact,
    AttackPrediction,
    RiskForecast,
    ForecastingMetrics,
)
from .store import get_forecasting_store, ThreatForecastingStore, reset_forecasting_store


class ThreatForecastingService:
    """Core threat forecasting service."""

    def __init__(self, store: Optional[ThreatForecastingStore] = None):
        self._store = store or get_forecasting_store()

    def create_forecast(
        self,
        threat_type: str,
        description: str,
        predicted_impact: str,
        confidence: float = 0.0,
        time_horizon_days: int = 30,
    ) -> ThreatForecast:
        """Create a threat forecast."""
        forecast = ThreatForecast(
            threat_type=threat_type,
            description=description,
            predicted_impact=predicted_impact,
            confidence=confidence,
            time_horizon_days=time_horizon_days,
        )
        self._store.store_forecast(forecast)
        return forecast

    def get_forecast(self, forecast_id: str) -> Optional[ThreatForecast]:
        """Get forecast by ID."""
        return self._store.get_forecast(forecast_id)

    def get_all_forecasts(self) -> List[ThreatForecast]:
        """Get all forecasts."""
        return self._store.get_all_forecasts()

    def predict_campaign(
        self,
        campaign_name: str,
        attack_vector: str,
        expected_scale: str,
        predicted_start: datetime,
    ) -> CampaignPrediction:
        """Predict a campaign."""
        campaign = CampaignPrediction(
            campaign_name=campaign_name,
            attack_vector=attack_vector,
            likelihood=0.7,
            expected_scale=expected_scale,
            predicted_start=predicted_start,
        )
        self._store.store_campaign(campaign)
        return campaign

    def analyze_trend(
        self,
        metric_name: str,
        trend_direction: str,
        change_percentage: float,
    ) -> TrendAnalysis:
        """Analyze a trend."""
        trend = TrendAnalysis(
            metric_name=metric_name,
            trend_direction=trend_direction,
            change_percentage=change_percentage,
        )
        self._store.store_trend(trend)
        return trend

    def estimate_impact(
        self,
        threat_type: str,
        estimated_loss_min: float,
        estimated_loss_max: float,
    ) -> EconomicImpact:
        """Estimate economic impact."""
        impact = EconomicImpact(
            threat_type=threat_type,
            estimated_loss_min=estimated_loss_min,
            estimated_loss_max=estimated_loss_max,
        )
        self._store.store_impact(impact)
        return impact

    def predict_attack(
        self,
        attack_type: str,
        precursor_indicators: List[str],
    ) -> AttackPrediction:
        """Predict an attack."""
        attack = AttackPrediction(
            attack_type=attack_type,
            precursor_indicators=precursor_indicators,
            probability=0.6,
        )
        self._store.store_attack(attack)
        return attack

    def create_risk_forecast(
        self,
        risk_category: str,
        risk_level: str,
        forecast_value: float,
        confidence: float = 0.0,
    ) -> RiskForecast:
        """Create a risk forecast."""
        risk = RiskForecast(
            risk_category=risk_category,
            risk_level=risk_level,
            forecast_value=forecast_value,
            confidence=confidence,
        )
        self._store.store_risk(risk)
        return risk

    def get_risk_forecast(self, forecast_id: str) -> Optional[RiskForecast]:
        """Get risk forecast by ID."""
        return self._store.get_risk(forecast_id)

    def get_metrics(self) -> ForecastingMetrics:
        """Get forecasting metrics."""
        metrics_dict = self._store.get_metrics()
        return ForecastingMetrics(**metrics_dict)

    def clear(self) -> None:
        """Clear all data."""
        reset_forecasting_store()


_forecasting_service: Optional[ThreatForecastingService] = None


def get_forecasting_service() -> ThreatForecastingService:
    global _forecasting_service
    if _forecasting_service is None:
        _forecasting_service = ThreatForecastingService()
    return _forecasting_service


def reset_forecasting_service() -> None:
    global _forecasting_service
    _forecasting_service = None
    reset_forecasting_store()
