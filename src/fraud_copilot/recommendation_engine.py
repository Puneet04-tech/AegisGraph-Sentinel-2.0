"""
Recommendation Engine.

AI-powered recommendation generation for investigations.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import uuid

from .models import Recommendation, RecommendationType
from .store import FraudCopilotStore, get_copilot_store


class RecommendationEngine:
    """Engine for generating investigation recommendations."""

    def __init__(self, store: Optional[FraudCopilotStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_copilot_store()

    async def generate_recommendations(
        self,
        case_id: str,
        case_data: Dict[str, Any],
    ) -> List[Recommendation]:
        """Generate recommendations based on case data."""
        recommendations = []
        
        risk_score = case_data.get("risk_score", 0.5)
        
        if risk_score > 0.7:
            recommendations.append(Recommendation(
                recommendation_id=str(uuid.uuid4()),
                case_id=case_id,
                recommendation_type=RecommendationType.ESCALATION,
                title="High Risk - Escalate Immediately",
                description="This case has high risk indicators. Immediate escalation to senior analyst required.",
                priority=1,
                confidence=0.92,
                supporting_evidence=["Risk score > 0.7", "Multiple risk factors present"],
            ))
        
        recommendations.append(Recommendation(
            recommendation_id=str(uuid.uuid4()),
            case_id=case_id,
            recommendation_type=RecommendationType.INVESTIGATION,
            title="Conduct Comprehensive Transaction Analysis",
            description="Review all recent transactions for anomalies, velocity patterns, and geographic inconsistencies.",
            priority=2,
            confidence=0.85,
            supporting_evidence=["Standard investigation protocol"],
        ))
        
        if case_data.get("linked_entities", 0) > 3:
            recommendations.append(Recommendation(
                recommendation_id=str(uuid.uuid4()),
                case_id=case_id,
                recommendation_type=RecommendationType.INVESTIGATION,
                title="Network Analysis Required",
                description="Multiple linked entities detected. Perform entity relationship mapping.",
                priority=2,
                confidence=0.88,
                supporting_evidence=["Multiple linked entities"],
            ))
        
        recommendations.append(Recommendation(
            recommendation_id=str(uuid.uuid4()),
            case_id=case_id,
            recommendation_type=RecommendationType.ENHANCED_MONITORING,
            title="Enable Real-Time Monitoring",
            description="Set up automated alerts for suspicious activity patterns.",
            priority=3,
            confidence=0.80,
        ))
        
        recommendations.append(Recommendation(
            recommendation_id=str(uuid.uuid4()),
            case_id=case_id,
            recommendation_type=RecommendationType.THREAT_HUNTING,
            title="Proactive Threat Hunting",
            description="Search for related indicators across the fraud network.",
            priority=4,
            confidence=0.75,
        ))
        
        for rec in recommendations:
            self.store.store_recommendation(case_id, rec)
        
        return recommendations

    async def get_prioritized_recommendations(
        self,
        case_id: str,
    ) -> List[Dict[str, Any]]:
        """Get prioritized recommendations for a case."""
        recommendations = self.store.get_recommendations(case_id)
        
        if not recommendations:
            return []
        
        recommendations.sort(key=lambda r: (r.priority, -r.confidence))
        
        return [
            {
                "id": r.recommendation_id,
                "type": r.recommendation_type.value,
                "title": r.title,
                "description": r.description,
                "priority": r.priority,
                "confidence": r.confidence,
                "evidence": r.supporting_evidence,
            }
            for r in recommendations
        ]

    async def validate_recommendation(
        self,
        recommendation_id: str,
        case_id: str,
    ) -> Dict[str, Any]:
        """Validate if a recommendation is still applicable."""
        recommendations = self.store.get_recommendations(case_id)
        
        for rec in recommendations:
            if rec.recommendation_id == recommendation_id:
                return {
                    "valid": True,
                    "recommendation": {
                        "id": rec.recommendation_id,
                        "title": rec.title,
                        "priority": rec.priority,
                    },
                }
        
        return {"valid": False, "reason": "Recommendation not found"}


# Singleton instance
_engine: Optional[RecommendationEngine] = None


def get_recommendation_engine() -> RecommendationEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = RecommendationEngine()
    return _engine


def reset_recommendation_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None