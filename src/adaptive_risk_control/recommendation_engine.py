"""
Policy Recommendation Engine for AI-driven recommendations.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import uuid

from .models import (
    RiskRecommendation,
    RiskLevel,
    TransactionAssessment,
)


class PolicyRecommendationEngine:
    """
    Provides AI-driven policy recommendations.

    Handles:
    - Policy optimization
    - Rule recommendations
    - Risk forecasting
    - Performance analysis
    """

    def __init__(self):
        self._recommendation_templates = self._initialize_templates()

    def _initialize_templates(self) -> Dict[str, List[str]]:
        """Initialize recommendation templates."""
        return {
            "threshold_adjustment": [
                "Consider reducing threshold for {} risk transactions",
                "Increase threshold to reduce false positives",
            ],
            "new_rule": [
                "Add control rule for {} indicators",
                "Create new rule for {} pattern",
            ],
            "policy_optimization": [
                "Optimize policy for better coverage",
                "Simplify policy conditions",
            ],
        }

    async def generate_recommendations(
        self,
        entity_id: str,
        recent_assessments: List[TransactionAssessment],
    ) -> List[RiskRecommendation]:
        """Generate policy recommendations based on patterns."""
        recommendations = []

        # Analyze patterns
        patterns = self._analyze_patterns(recent_assessments)

        for pattern in patterns:
            recommendation = RiskRecommendation(
                recommendation_id=str(uuid.uuid4()),
                entity_id=entity_id,
                recommendation_type=pattern["type"],
                description=pattern["description"],
                priority=pattern["priority"],
                actions=pattern["actions"],
                expected_impact=pattern["impact"],
                risk_reduction=pattern["risk_reduction"],
            )
            recommendations.append(recommendation)

        return recommendations

    def _analyze_patterns(
        self,
        assessments: List[TransactionAssessment],
    ) -> List[Dict[str, Any]]:
        """Analyze patterns in assessments."""
        patterns = []

        if not assessments:
            return patterns

        # Find high-risk patterns
        high_risk = [a for a in assessments if a.risk_score > 0.7]
        if len(high_risk) > len(assessments) * 0.2:
            patterns.append({
                "type": "high_risk_trend",
                "description": "20%+ of transactions are high-risk",
                "priority": 1,
                "actions": [
                    "Review current thresholds",
                    "Add additional verification",
                    "Consider tightening controls",
                ],
                "impact": 0.3,
                "risk_reduction": 0.2,
            })

        # Find velocity patterns
        avg_velocity = sum(a.velocity_score for a in assessments) / len(assessments)
        if avg_velocity > 0.5:
            patterns.append({
                "type": "velocity_pattern",
                "description": "High average transaction velocity",
                "priority": 2,
                "actions": [
                    "Add velocity-based rule",
                    "Implement rate limiting",
                ],
                "impact": 0.2,
                "risk_reduction": 0.15,
            })

        # Find behavioral patterns
        high_behavior = [a for a in assessments if a.behavioral_score > 0.6]
        if len(high_behavior) > len(assessments) * 0.1:
            patterns.append({
                "type": "behavioral_anomaly",
                "description": "Behavioral anomalies detected",
                "priority": 1,
                "actions": [
                    "Update behavioral baseline",
                    "Add behavioral verification",
                ],
                "impact": 0.25,
                "risk_reduction": 0.18,
            })

        return patterns

    async def suggest_threshold_adjustments(
        self,
        current_threshold: float,
        recent_decisions: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Suggest threshold adjustments based on performance."""
        if not recent_decisions:
            return {"suggestion": "insufficient_data"}

        # Calculate false positive rate
        false_positives = sum(
            1 for d in recent_decisions
            if d.get("blocked") and not d.get("actual_fraud")
        )
        false_positive_rate = false_positives / len(recent_decisions) if recent_decisions else 0

        # Calculate false negative rate
        false_negatives = sum(
            1 for d in recent_decisions
            if not d.get("blocked") and d.get("actual_fraud")
        )
        false_negative_rate = false_negatives / len(recent_decisions) if recent_decisions else 0

        # Determine adjustment
        if false_positive_rate > 0.1:
            adjustment = 0.05
            direction = "increase"
        elif false_negative_rate > 0.05:
            adjustment = 0.05
            direction = "decrease"
        else:
            return {
                "suggestion": "maintain",
                "current_threshold": current_threshold,
                "reason": "Current threshold performing well",
            }

        new_threshold = current_threshold + adjustment if direction == "increase" else current_threshold - adjustment

        return {
            "suggestion": "adjust",
            "direction": direction,
            "adjustment": adjustment,
            "current_threshold": current_threshold,
            "new_threshold": new_threshold,
            "reason": f"False positive rate: {false_positive_rate:.2%}, "
                      f"False negative rate: {false_negative_rate:.2%}",
        }

    async def recommend_new_rules(
        self,
        patterns: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Recommend new control rules based on patterns."""
        recommendations = []

        for pattern in patterns:
            if pattern["type"] == "high_risk_trend":
                recommendations.append({
                    "rule_type": "threshold",
                    "name": "High Risk Transaction Rule",
                    "conditions": {"risk_score_min": 0.7},
                    "action": "challenge",
                    "priority": 1,
                })

            if pattern["type"] == "velocity_pattern":
                recommendations.append({
                    "rule_type": "velocity",
                    "name": "Velocity Limit Rule",
                    "conditions": {"velocity_threshold": 5},
                    "action": "block",
                    "priority": 2,
                })

        return recommendations

    async def forecast_risk(
        self,
        entity_id: str,
        historical_data: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Forecast future risk levels."""
        if not historical_data:
            return {
                "forecast_risk_level": "unknown",
                "confidence": 0,
            }

        # Simple forecast based on trend
        risk_scores = [d.get("risk_score", 0.5) for d in historical_data]
        avg_risk = sum(risk_scores) / len(risk_scores)

        # Calculate trend
        if len(risk_scores) >= 3:
            recent_avg = sum(risk_scores[-3:]) / 3
            trend = "increasing" if recent_avg > avg_risk else "decreasing"
        else:
            trend = "stable"

        # Determine forecast
        if avg_risk > 0.7 or trend == "increasing":
            forecast_level = RiskLevel.HIGH
        elif avg_risk > 0.5:
            forecast_level = RiskLevel.MEDIUM
        else:
            forecast_level = RiskLevel.LOW

        return {
            "forecast_risk_level": forecast_level.value,
            "expected_risk_score": avg_risk,
            "trend": trend,
            "confidence": 0.7 if len(historical_data) > 10 else 0.5,
        }


# Global engine instance
_engine: Optional[PolicyRecommendationEngine] = None


def get_recommendation_engine() -> PolicyRecommendationEngine:
    """Get the recommendation engine instance."""
    global _engine
    if _engine is None:
        _engine = PolicyRecommendationEngine()
    return _engine