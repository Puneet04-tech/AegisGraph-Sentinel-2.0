"""
Threat Forecasting Engine.

Predicts future threats based on patterns and intelligence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import FraudCampaign, ThreatForecast, ThreatIntelligence
from .store import GlobalDefenseStore, get_global_defense_store


@dataclass
class ForecastConfidence:
    """Confidence metrics for forecast."""
    base_confidence: float
    trend_factor: float
    pattern_factor: float
    historical_factor: float


class ThreatForecastEngine:
    """Engine for forecasting emerging threats."""

    def __init__(self, store: Optional[GlobalDefenseStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_global_defense_store()

    async def generate_forecast(
        self,
        period: str = "7d",
        min_confidence: float = 0.5,
    ) -> List[ThreatForecast]:
        """Generate threat forecasts."""
        forecasts: List[ThreatForecast] = []
        
        trend_analysis = self._analyze_trends()
        
        for threat_type, trend_data in trend_analysis.items():
            if trend_data["probability"] >= min_confidence:
                forecast = ThreatForecast(
                    forecast_id=str(uuid.uuid4()),
                    predicted_threat_type=threat_type,
                    probability=trend_data["probability"],
                    confidence=trend_data["confidence"],
                    predicted_impact=trend_data.get("impact", 0.5),
                    affected_regions=trend_data.get("regions", []),
                    recommended_actions=self._generate_recommendations(threat_type, trend_data),
                    forecast_period=period,
                )
                forecasts.append(forecast)
                self.store.store_forecast(forecast)
        
        return forecasts

    def _analyze_trends(self) -> Dict[str, Dict[str, Any]]:
        """Analyze threat trends from intelligence."""
        trends: Dict[str, Dict[str, Any]] = {}
        
        intel_list = list(self.store._intelligence.values())
        
        type_groups: Dict[str, List[ThreatIntelligence]] = {}
        for intel in intel_list:
            type_groups.setdefault(intel.threat_type, []).append(intel)
        
        for threat_type, intels in type_groups.items():
            recent_count = len([
                i for i in intels
                if (datetime.now(timezone.utc) - i.created_at).days <= 7
            ])
            total_count = len(intels)
            
            avg_confidence = sum(i.confidence for i in intels) / total_count if intels else 0.5
            
            probability = min(0.95, avg_confidence * (1 + recent_count * 0.1))
            
            regions = set()
            for intel in intels:
                for ind in intel.indicators:
                    if "region" in ind:
                        regions.add(ind["region"])
            
            trends[threat_type] = {
                "probability": probability,
                "confidence": avg_confidence,
                "regions": list(regions)[:5],
                "impact": min(1.0, avg_confidence * 1.2),
                "recent_count": recent_count,
                "total_count": total_count,
            }
        
        return trends

    def _generate_recommendations(
        self,
        threat_type: str,
        trend_data: Dict[str, Any],
    ) -> List[str]:
        """Generate recommendations for a threat type."""
        recommendations = []
        probability = trend_data.get("probability", 0.5)
        
        if probability > 0.8:
            recommendations.append(f"URGENT: High probability {threat_type} threat predicted")
            recommendations.append("Activate emergency response protocols")
            recommendations.append("Increase monitoring across all regions")
        elif probability > 0.6:
            recommendations.append(f"Alert: Elevated {threat_type} activity expected")
            recommendations.append("Prepare defensive measures")
            recommendations.append("Review recent intelligence from affiliated institutions")
        else:
            recommendations.append(f"Monitor: Watch for {threat_type} indicators")
            recommendations.append("Continue standard threat intelligence sharing")
        
        regions = trend_data.get("regions", [])
        if regions:
            recommendations.append(f"Focus monitoring on: {', '.join(regions[:3])}")
        
        return recommendations

    async def predict_campaign_emergence(
        self,
        indicator_patterns: List[str],
    ) -> Optional[ThreatForecast]:
        """Predict if a campaign is emerging based on patterns."""
        matching_intel = 0
        for pattern in indicator_patterns:
            for intel in self.store._intelligence.values():
                if any(pattern in str(ind) for ind in intel.indicators):
                    matching_intel += 1
        
        if matching_intel >= 3:
            avg_confidence = sum(
                i.confidence for i in self.store._intelligence.values()
                if any(pattern in str(ind) for ind in i.indicators)
            ) / matching_intel
            
            return ThreatForecast(
                forecast_id=str(uuid.uuid4()),
                predicted_threat_type="emerging_campaign",
                probability=min(0.9, avg_confidence + 0.1),
                confidence=avg_confidence * 0.8,
                predicted_impact=0.7,
                affected_regions=[],
                recommended_actions=[
                    "Investigate indicator patterns across institutions",
                    "Coordinate with affiliated organizations",
                    "Prepare containment measures",
                ],
                forecast_period="3d",
            )
        
        return None

    def get_forecast_summary(self) -> Dict[str, Any]:
        """Get summary of all forecasts."""
        forecasts = list(self.store._forecasts.values())
        
        by_type: Dict[str, int] = {}
        for f in forecasts:
            by_type[f.predicted_threat_type] = by_type.get(f.predicted_threat_type, 0) + 1
        
        high_prob = [f for f in forecasts if f.probability > 0.7]
        
        return {
            "total_forecasts": len(forecasts),
            "forecasts_by_type": by_type,
            "high_probability_count": len(high_prob),
            "avg_confidence": sum(f.confidence for f in forecasts) / len(forecasts) if forecasts else 0,
        }


# Singleton instance
_engine: Optional[ThreatForecastEngine] = None


def get_threat_forecast_engine() -> ThreatForecastEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = ThreatForecastEngine()
    return _engine


def reset_threat_forecast_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None