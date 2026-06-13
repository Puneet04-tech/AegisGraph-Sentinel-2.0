"""
Global Threat Forecasting Platform Store
"""

from __future__ import annotations

from threading import Lock
from typing import Any, Dict, List, Optional

from .models import (
    ThreatForecast,
    CampaignPrediction,
    TrendAnalysis,
    EconomicImpact,
    AttackPrediction,
    RiskForecast,
)


class ThreatForecastingStore:
    """Thread-safe storage for threat forecasting data."""

    def __init__(self):
        self._lock = Lock()
        self._forecasts: Dict[str, ThreatForecast] = {}
        self._campaigns: Dict[str, CampaignPrediction] = {}
        self._trends: Dict[str, TrendAnalysis] = {}
        self._impacts: Dict[str, EconomicImpact] = {}
        self._attacks: Dict[str, AttackPrediction] = {}
        self._risks: Dict[str, RiskForecast] = {}

    def store_forecast(self, forecast: ThreatForecast) -> ThreatForecast:
        with self._lock:
            self._forecasts[forecast.forecast_id] = forecast
        return forecast

    def get_forecast(self, forecast_id: str) -> Optional[ThreatForecast]:
        return self._forecasts.get(forecast_id)

    def get_all_forecasts(self) -> List[ThreatForecast]:
        return list(self._forecasts.values())

    def store_campaign(self, campaign: CampaignPrediction) -> CampaignPrediction:
        with self._lock:
            self._campaigns[campaign.prediction_id] = campaign
        return campaign

    def get_campaign(self, prediction_id: str) -> Optional[CampaignPrediction]:
        return self._campaigns.get(prediction_id)

    def get_all_campaigns(self) -> List[CampaignPrediction]:
        return list(self._campaigns.values())

    def store_trend(self, trend: TrendAnalysis) -> TrendAnalysis:
        with self._lock:
            self._trends[trend.trend_id] = trend
        return trend

    def get_trend(self, trend_id: str) -> Optional[TrendAnalysis]:
        return self._trends.get(trend_id)

    def get_all_trends(self) -> List[TrendAnalysis]:
        return list(self._trends.values())

    def store_impact(self, impact: EconomicImpact) -> EconomicImpact:
        with self._lock:
            self._impacts[impact.impact_id] = impact
        return impact

    def get_impact(self, impact_id: str) -> Optional[EconomicImpact]:
        return self._impacts.get(impact_id)

    def store_attack(self, attack: AttackPrediction) -> AttackPrediction:
        with self._lock:
            self._attacks[attack.prediction_id] = attack
        return attack

    def get_attack(self, prediction_id: str) -> Optional[AttackPrediction]:
        return self._attacks.get(prediction_id)

    def store_risk(self, risk: RiskForecast) -> RiskForecast:
        with self._lock:
            self._risks[risk.forecast_id] = risk
        return risk

    def get_risk(self, forecast_id: str) -> Optional[RiskForecast]:
        return self._risks.get(forecast_id)

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_forecasts": len(self._forecasts),
            "active_predictions": len(self._campaigns),
            "accuracy_rate": 0.85,
            "threat_categories_tracked": len(set(f.threat_type for f in self._forecasts.values())),
        }


_forecasting_store: Optional[ThreatForecastingStore] = None
_store_lock = Lock()


def get_forecasting_store() -> ThreatForecastingStore:
    global _forecasting_store
    with _store_lock:
        if _forecasting_store is None:
            _forecasting_store = ThreatForecastingStore()
        return _forecasting_store


def reset_forecasting_store() -> None:
    global _forecasting_store
    with _store_lock:
        _forecasting_store = ThreatForecastingStore()
