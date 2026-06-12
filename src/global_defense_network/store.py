"""
Global Defense Network Store.

Storage for federated intelligence and network data.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    CrossCorrelation,
    DefenseConfig,
    FraudCampaign,
    Institution,
    NetworkMetrics,
    ThreatForecast,
    ThreatIntelligence,
    TrustLevel,
)


class GlobalDefenseStore:
    """Store for global defense network."""

    def __init__(self) -> None:
        """Initialize the store."""
        self._institutions: Dict[str, Institution] = {}
        self._intelligence: Dict[str, ThreatIntelligence] = {}
        self._campaigns: Dict[str, FraudCampaign] = {}
        self._forecasts: Dict[str, ThreatForecast] = {}
        self._correlations: Dict[str, CrossCorrelation] = {}
        self._config = DefenseConfig()
        self._lock = threading.RLock()

    def add_institution(self, institution: Institution) -> None:
        """Add an institution to the network."""
        with self._lock:
            self._institutions[institution.institution_id] = institution

    def get_institution(self, institution_id: str) -> Optional[Institution]:
        """Get an institution by ID."""
        return self._institutions.get(institution_id)

    def get_all_institutions(self) -> List[Institution]:
        """Get all institutions."""
        return list(self._institutions.values())

    def get_trusted_institutions(self, min_trust: TrustLevel = TrustLevel.TRUSTED) -> List[Institution]:
        """Get institutions above trust threshold."""
        trust_values = {
            TrustLevel.RESTRICTED: 0,
            TrustLevel.PROVISIONAL: 1,
            TrustLevel.TRUSTED: 2,
            TrustLevel.VERIFIED: 3,
        }
        min_level = trust_values.get(min_trust, 1)
        return [
            i for i in self._institutions.values()
            if trust_values.get(i.trust_level, 0) >= min_level
        ]

    def store_intelligence(self, intelligence: ThreatIntelligence) -> None:
        """Store threat intelligence."""
        with self._lock:
            self._intelligence[intelligence.intelligence_id] = intelligence

    def get_intelligence(self, intelligence_id: str) -> Optional[ThreatIntelligence]:
        """Get intelligence by ID."""
        return self._intelligence.get(intelligence_id)

    def get_intelligence_by_type(self, threat_type: str) -> List[ThreatIntelligence]:
        """Get intelligence by threat type."""
        return [
            i for i in self._intelligence.values()
            if i.threat_type == threat_type
        ]

    def get_active_intelligence(self, hours: int = 24) -> List[ThreatIntelligence]:
        """Get active intelligence within time window."""
        cutoff = datetime.now(timezone.utc).timestamp() - (hours * 3600)
        return [
            i for i in self._intelligence.values()
            if i.created_at.timestamp() >= cutoff or
            (i.expires_at and i.expires_at.timestamp() > datetime.now(timezone.utc).timestamp())
        ]

    def store_campaign(self, campaign: FraudCampaign) -> None:
        """Store fraud campaign."""
        with self._lock:
            self._campaigns[campaign.campaign_id] = campaign

    def get_campaign(self, campaign_id: str) -> Optional[FraudCampaign]:
        """Get campaign by ID."""
        return self._campaigns.get(campaign_id)

    def get_active_campaigns(self) -> List[FraudCampaign]:
        """Get all active campaigns."""
        return [
            c for c in self._campaigns.values()
            if c.status.value == "active"
        ]

    def store_forecast(self, forecast: ThreatForecast) -> None:
        """Store threat forecast."""
        with self._lock:
            self._forecasts[forecast.forecast_id] = forecast

    def get_recent_forecasts(self, limit: int = 10) -> List[ThreatForecast]:
        """Get recent forecasts."""
        sorted_forecasts = sorted(
            self._forecasts.values(),
            key=lambda f: f.generated_at,
            reverse=True,
        )
        return sorted_forecasts[:limit]

    def store_correlation(self, correlation: CrossCorrelation) -> None:
        """Store cross-correlation."""
        with self._lock:
            self._correlations[correlation.correlation_id] = correlation

    def get_correlations_for_institution(self, institution_id: str) -> List[CrossCorrelation]:
        """Get correlations involving an institution."""
        return [
            c for c in self._correlations.values()
            if c.institution_1 == institution_id or c.institution_2 == institution_id
        ]

    def get_network_metrics(self) -> NetworkMetrics:
        """Get network metrics."""
        institutions = list(self._institutions.values())
        avg_trust = sum(i.reputation_score for i in institutions) / len(institutions) if institutions else 0.5
        
        return NetworkMetrics(
            total_institutions=len(institutions),
            active_threats=len([i for i in self._intelligence.values() if i.confidence > 0.7]),
            campaigns_tracked=len(self._campaigns),
            intelligence_shared=len(self._intelligence),
            threats_forecasted=len(self._forecasts),
            response_coordination=len(self._correlations),
            avg_trust_score=avg_trust,
        )

    def clear(self) -> None:
        """Clear all data."""
        with self._lock:
            self._institutions.clear()
            self._intelligence.clear()
            self._campaigns.clear()
            self._forecasts.clear()
            self._correlations.clear()


# Singleton instance
_store: Optional[GlobalDefenseStore] = None
_store_lock = threading.Lock()


def get_global_defense_store() -> GlobalDefenseStore:
    """Get the global store instance."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = GlobalDefenseStore()
    return _store


def reset_global_defense_store() -> None:
    """Reset the global store."""
    global _store
    with _store_lock:
        if _store is not None:
            _store.clear()
        _store = None