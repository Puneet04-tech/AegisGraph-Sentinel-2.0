"""
Risk Scoring Engine.

Calculates overall digital risk scores.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid

from .models import RiskScore
from .store import DRPStore, get_drp_store


class RiskScoringEngine:
    """Engine for digital risk scoring."""

    def __init__(self, store: Optional[DRPStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_drp_store()

    def calculate_risk_score(self, organization_id: str) -> RiskScore:
        """Calculate overall risk score for an organization."""
        phishing_alerts = self.store.get_phishing_alerts()
        active_phishing = [
            a for a in phishing_alerts
            if a.risk_level.value in ["critical", "high"]
        ]
        phishing_score = min(1.0, len(active_phishing) * 0.1)
        
        brand_impersonations = self.store.get_brand_impersonations()
        brand_risk = min(1.0, len(brand_impersonations) * 0.15)
        
        credential_exposures = self.store.get_credential_exposures()
        credential_risk = min(1.0, len(credential_exposures) * 0.2)
        
        darkweb_intel = self.store.get_darkweb_intel(0.6)
        darkweb_risk = min(1.0, len(darkweb_intel) * 0.15)
        
        social_abuse = self.store.get_social_abuse()
        social_risk = min(1.0, len(social_abuse) * 0.1)
        
        attack_surfaces = self.store.get_attack_surfaces()
        surface_risk = min(
            1.0,
            sum(s.risk_score for s in attack_surfaces) / max(1, len(attack_surfaces))
        )
        
        overall = (
            phishing_score * 0.25 +
            brand_risk * 0.15 +
            credential_risk * 0.25 +
            darkweb_risk * 0.15 +
            social_risk * 0.1 +
            surface_risk * 0.1
        )
        
        score = RiskScore(
            score_id=str(uuid.uuid4()),
            organization_id=organization_id,
            overall_score=overall,
            phishing_score=phishing_score,
            brand_risk_score=brand_risk,
            credential_risk_score=credential_risk,
            dark_web_risk_score=darkweb_risk,
            social_media_risk_score=social_risk,
            attack_surface_score=surface_risk,
        )
        
        self.store.store_risk_score(score)
        
        return score

    def get_risk_score(self, organization_id: str) -> Optional[Dict[str, Any]]:
        """Get risk score for an organization."""
        score = self.store.get_risk_score(organization_id)
        if not score:
            return None
        
        return {
            "score_id": score.score_id,
            "organization_id": score.organization_id,
            "overall_score": score.overall_score,
            "component_scores": {
                "phishing": score.phishing_score,
                "brand_risk": score.brand_risk_score,
                "credential_risk": score.credential_risk_score,
                "dark_web": score.dark_web_risk_score,
                "social_media": score.social_media_risk_score,
                "attack_surface": score.attack_surface_score,
            },
            "risk_level": self._score_to_risk_level(score.overall_score),
            "calculated_at": score.calculated_at.isoformat(),
        }

    def _score_to_risk_level(self, score: float) -> str:
        """Convert score to risk level string."""
        if score >= 0.7:
            return "critical"
        elif score >= 0.5:
            return "high"
        elif score >= 0.3:
            return "medium"
        elif score >= 0.1:
            return "low"
        return "minimal"


# Singleton instance
_engine: Optional[RiskScoringEngine] = None


def get_risk_engine() -> RiskScoringEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = RiskScoringEngine()
    return _engine


def reset_risk_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None