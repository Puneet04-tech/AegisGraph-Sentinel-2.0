"""
Global AI Fraud Defense Network Service.

Main service for the distributed fraud defense ecosystem.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    DefenseConfig,
    DefenseResponse,
    FraudCampaign,
    Institution,
    NetworkMetrics,
    ThreatCampaignStatus,
    TrustLevel,
)
from .store import (
    GlobalDefenseStore,
    get_global_defense_store,
    reset_global_defense_store,
)
from .federated_hub import (
    FederatedIntelligenceHub,
    get_federated_intelligence_hub,
    reset_federated_intelligence_hub,
)
from .correlation_engine import (
    ThreatCorrelationEngine,
    get_threat_correlation_engine,
    reset_threat_correlation_engine,
)
from .forecast_engine import (
    ThreatForecastEngine,
    get_threat_forecast_engine,
    reset_threat_forecast_engine,
)


class GlobalDefenseNetwork:
    """Main service for global AI fraud defense network."""

    def __init__(self, store: Optional[GlobalDefenseStore] = None) -> None:
        """Initialize the network."""
        self.store = store or get_global_defense_store()
        self.hub = get_federated_intelligence_hub()
        self.correlation = get_threat_correlation_engine()
        self.forecast = get_threat_forecast_engine()

    async def share_intelligence(
        self,
        institution_id: str,
        threat_type: str,
        indicators: List[Dict[str, Any]],
        confidence: float,
        sharing_level: str = "anonymized",
    ) -> Dict[str, Any]:
        """Share threat intelligence with the network."""
        intelligence = await self.hub.share_intelligence(
            source_institution=institution_id,
            threat_type=threat_type,
            indicators=indicators,
            confidence=confidence,
            sharing_level=sharing_level,
        )
        
        return {
            "intelligence_id": intelligence.intelligence_id,
            "status": "shared",
            "sharing_level": intelligence.sharing_level.value,
            "confidence": intelligence.confidence,
        }

    async def get_intelligence(
        self,
        threat_type: Optional[str] = None,
        min_confidence: float = 0.5,
    ) -> List[Dict[str, Any]]:
        """Get threat intelligence from network."""
        intelligence = self.hub.get_network_intelligence(
            threat_type=threat_type,
            min_confidence=min_confidence,
        )
        
        return [
            {
                "intelligence_id": i.intelligence_id,
                "threat_type": i.threat_type,
                "source": i.source_institution,
                "confidence": i.confidence,
                "sharing_level": i.sharing_level.value,
                "created_at": i.created_at.isoformat(),
            }
            for i in intelligence
        ]

    async def correlate_threats(
        self,
        institution_1: str,
        institution_2: str,
    ) -> Dict[str, Any]:
        """Correlate threats between institutions."""
        correlation = await self.correlation.correlate_threats(
            institution_1=institution_1,
            institution_2=institution_2,
        )
        
        return {
            "correlation_id": correlation.correlation_id,
            "institution_1": correlation.institution_1,
            "institution_2": correlation.institution_2,
            "confidence": correlation.confidence,
            "threat_level": correlation.threat_level,
            "shared_indicators": correlation.shared_indicators,
        }

    async def get_campaigns(
        self,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get fraud campaigns."""
        if status:
            campaigns = [c for c in self.store.get_active_campaigns() if c.status.value == status]
        else:
            campaigns = list(self.store._campaigns.values())
        
        return [
            {
                "campaign_id": c.campaign_id,
                "name": c.name,
                "status": c.status.value,
                "threat_level": c.threat_level,
                "affected_institutions": c.affected_institutions,
                "first_detected": c.first_detected.isoformat(),
            }
            for c in campaigns
        ]

    async def get_forecasts(
        self,
        period: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get threat forecasts."""
        forecasts = self.store.get_recent_forecasts()
        
        if period:
            forecasts = [f for f in forecasts if f.forecast_period == period]
        
        return [
            {
                "forecast_id": f.forecast_id,
                "threat_type": f.predicted_threat_type,
                "probability": f.probability,
                "confidence": f.confidence,
                "regions": f.affected_regions,
                "recommended_actions": f.recommended_actions,
            }
            for f in forecasts
        ]

    async def generate_forecast(
        self,
        period: str = "7d",
    ) -> List[Dict[str, Any]]:
        """Generate new threat forecasts."""
        forecasts = await self.forecast.generate_forecast(period=period)
        
        return [
            {
                "forecast_id": f.forecast_id,
                "threat_type": f.predicted_threat_type,
                "probability": f.probability,
                "confidence": f.confidence,
            }
            for f in forecasts
        ]

    async def respond_to_campaign(
        self,
        campaign_id: str,
        response_type: str,
    ) -> Dict[str, Any]:
        """Generate and coordinate response to a campaign."""
        campaign = self.store.get_campaign(campaign_id)
        
        if not campaign:
            return {"error": "Campaign not found"}
        
        participating = campaign.affected_institutions[:5]
        
        response = DefenseResponse(
            response_id=str(uuid.uuid4()),
            campaign_id=campaign_id,
            response_type=response_type,
            recommended_actions=self._generate_response_actions(campaign),
            confidence=campaign.threat_level,
            coordination_required=len(participating) > 1,
            participating_institutions=participating,
        )
        
        return {
            "response_id": response.response_id,
            "campaign_id": campaign_id,
            "actions": response.recommended_actions,
            "coordination_required": response.coordination_required,
            "participants": participating,
        }

    def _generate_response_actions(self, campaign: FraudCampaign) -> List[Dict[str, Any]]:
        """Generate response actions for a campaign."""
        actions = []
        
        if campaign.threat_level > 0.8:
            actions.append({
                "action": "EMERGENCY_RESPONSE",
                "description": "Activate emergency fraud prevention protocols",
                "priority": "critical",
            })
        
        actions.append({
            "action": "SHARE_INTELLIGENCE",
            "description": "Share campaign indicators with network",
            "priority": "high",
        })
        
        actions.append({
            "action": "INCREASE_MONITORING",
            "description": "Increase transaction monitoring for affected regions",
            "priority": "high",
        })
        
        actions.append({
            "action": "COORDINATE_RESPONSE",
            "description": "Contact affected institutions for coordinated response",
            "priority": "medium",
        })
        
        return actions

    async def get_network_status(self) -> Dict[str, Any]:
        """Get network status and metrics."""
        metrics = self.store.get_network_metrics()
        contributions = self.hub.get_contribution_summary()
        
        return {
            "metrics": {
                "total_institutions": metrics.total_institutions,
                "active_threats": metrics.active_threats,
                "campaigns_tracked": metrics.campaigns_tracked,
                "intelligence_shared": metrics.intelligence_shared,
                "avg_trust_score": metrics.avg_trust_score,
            },
            "contributions": [
                {"institution": c.institution_id, "count": c.intelligence_count}
                for c in contributions[:10]
            ],
            "forecasts": self.forecast.get_forecast_summary(),
        }

    async def get_dashboard(self) -> Dict[str, Any]:
        """Get global defense dashboard."""
        metrics = self.store.get_network_metrics()
        campaigns = self.store.get_active_campaigns()
        forecasts = self.store.get_recent_forecasts(limit=5)
        
        return {
            "network_metrics": {
                "institutions": metrics.total_institutions,
                "active_threats": metrics.active_threats,
                "campaigns": metrics.campaigns_tracked,
                "trust_score": metrics.avg_trust_score,
            },
            "active_campaigns": [
                {"id": c.campaign_id, "name": c.name, "level": c.threat_level}
                for c in campaigns[:10]
            ],
            "forecasts": [
                {"type": f.predicted_threat_type, "probability": f.probability}
                for f in forecasts
            ],
        }

    def add_institution(
        self,
        institution_id: str,
        name: str,
        trust_level: str = "provisional",
        capabilities: Optional[List[str]] = None,
        regions: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Add an institution to the network."""
        institution = Institution(
            institution_id=institution_id,
            name=name,
            trust_level=TrustLevel(trust_level),
            capabilities=capabilities or [],
            regions=regions or [],
        )
        
        self.store.add_institution(institution)
        
        return {
            "institution_id": institution_id,
            "status": "joined",
            "trust_level": trust_level,
        }


# Singleton instance
_service: Optional[GlobalDefenseNetwork] = None


def get_global_defense_network() -> GlobalDefenseNetwork:
    """Get the global service instance."""
    global _service
    if _service is None:
        _service = GlobalDefenseNetwork()
    return _service


def reset_global_defense_network() -> None:
    """Reset the global service."""
    global _service
    _service = None
    reset_global_defense_store()
    reset_federated_intelligence_hub()
    reset_threat_correlation_engine()
    reset_threat_forecast_engine()