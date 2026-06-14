"""
Threat Scoring Engine for AI Threat Hunting
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from .models import ThreatScore, ThreatSeverity, ThreatIndicator
from .store import ThreatHuntingStore, get_store


class ThreatScoringEngine:
    """Engine to calculate entity threat scores."""

    def __init__(self, store: Optional[ThreatHuntingStore] = None):
        self.store = store or get_store()
        self.weights = {
            "behavioral": 0.35,
            "campaign": 0.25,
            "graph": 0.20,
            "intelligence": 0.20,
        }

    def calculate_score(
        self,
        entity_id: str,
        entity_type: str = "user",
        behavior_score: float = 0.0,
        campaign_score: float = 0.0,
        graph_score: float = 0.0,
        intel_score: float = 0.0,
        active_indicators: Optional[List[str]] = None,
    ) -> ThreatScore:
        """Calculate and cache threat score for an entity."""
        active_indicators = active_indicators or []

        # Validate inputs
        behavior_score = max(0.0, min(1.0, behavior_score))
        campaign_score = max(0.0, min(1.0, campaign_score))
        graph_score = max(0.0, min(1.0, graph_score))
        intel_score = max(0.0, min(1.0, intel_score))

        breakdown = {
            "behavioral": behavior_score,
            "campaign": campaign_score,
            "graph": graph_score,
            "intelligence": intel_score,
        }

        # Weighted sum calculation
        total_score = (
            behavior_score * self.weights["behavioral"]
            + campaign_score * self.weights["campaign"]
            + graph_score * self.weights["graph"]
            + intel_score * self.weights["intelligence"]
        )

        total_score = max(0.0, min(1.0, total_score))
        severity = self._map_to_severity(total_score)

        threat_score = ThreatScore(
            entity_id=entity_id,
            entity_type=entity_type,
            score=total_score,
            severity=severity,
            breakdown=breakdown,
            active_indicators=active_indicators,
            calculated_at=datetime.now(timezone.utc).isoformat(),
        )

        self.store.set_threat_score(entity_id, threat_score)
        return threat_score

    def _map_to_severity(self, score: float) -> ThreatSeverity:
        if score < 0.25:
            return ThreatSeverity.LOW
        elif score < 0.50:
            return ThreatSeverity.MEDIUM
        elif score < 0.75:
            return ThreatSeverity.HIGH
        else:
            return ThreatSeverity.CRITICAL
