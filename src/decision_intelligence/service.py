"""
Autonomous Security Decision Engine Service - Core business logic
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import (
    SecurityRecommendation,
    MitigationAction,
    RiskDecision,
    ExplainabilityRecord,
    GovernanceDecision,
    DecisionMetrics,
    DecisionType,
    DecisionPriority,
    DecisionStatus,
)
from .store import get_decision_store, DecisionStore, reset_decision_store


class DecisionService:
    """Core decision intelligence service."""

    def __init__(self, store: Optional[DecisionStore] = None):
        self._store = store or get_decision_store()

    def generate_recommendation(
        self,
        title: str,
        description: str,
        decision_type: DecisionType,
        expected_outcome: str = "",
        confidence: float = 0.8,
        **kwargs: Any,
    ) -> SecurityRecommendation:
        """Generate a security recommendation."""
        priority = self._determine_priority(kwargs.get("risk_score", 0.5))

        recommendation = SecurityRecommendation(
            title=title,
            description=description,
            decision_type=decision_type,
            priority=priority,
            confidence=confidence,
            expected_outcome=expected_outcome,
            **kwargs,
        )
        self._store.store_recommendation(recommendation)
        return recommendation

    def _determine_priority(self, risk_score: float) -> DecisionPriority:
        """Determine priority from risk score."""
        if risk_score >= 0.9:
            return DecisionPriority.CRITICAL
        elif risk_score >= 0.7:
            return DecisionPriority.HIGH
        elif risk_score >= 0.4:
            return DecisionPriority.MEDIUM
        return DecisionPriority.LOW

    def get_recommendation(
        self, recommendation_id: str
    ) -> Optional[SecurityRecommendation]:
        """Get recommendation by ID."""
        return self._store.get_recommendation(recommendation_id)

    def get_recommendations(
        self,
        decision_type: Optional[DecisionType] = None,
        priority: Optional[DecisionPriority] = None,
        status: Optional[DecisionStatus] = None,
    ) -> List[SecurityRecommendation]:
        """Get recommendations with filters."""
        recommendations = self._store.get_all_recommendations()

        if decision_type:
            recommendations = [
                r for r in recommendations if r.decision_type == decision_type
            ]
        if priority:
            recommendations = [
                r for r in recommendations if r.priority == priority
            ]
        if status:
            recommendations = [
                r for r in recommendations if r.status == status
            ]

        return recommendations

    def approve_recommendation(
        self,
        recommendation_id: str,
        approver: str,
    ) -> Optional[SecurityRecommendation]:
        """Approve a recommendation."""
        recommendation = self._store.get_recommendation(recommendation_id)
        if recommendation:
            recommendation.status = DecisionStatus.APPROVED
            recommendation.decided_at = None
            self._store.store_recommendation(recommendation)
        return recommendation

    def reject_recommendation(
        self,
        recommendation_id: str,
        reason: str = "",
    ) -> Optional[SecurityRecommendation]:
        """Reject a recommendation."""
        recommendation = self._store.get_recommendation(recommendation_id)
        if recommendation:
            recommendation.status = DecisionStatus.REJECTED
            recommendation.reasoning = reason
            self._store.store_recommendation(recommendation)
        return recommendation

    def create_mitigation_action(
        self,
        recommendation_id: str,
        title: str,
        description: str,
        action_type: str,
        priority: DecisionPriority = DecisionPriority.MEDIUM,
        **kwargs: Any,
    ) -> MitigationAction:
        """Create a mitigation action."""
        action = MitigationAction(
            recommendation_id=recommendation_id,
            title=title,
            description=description,
            action_type=action_type,
            priority=priority,
            **kwargs,
        )
        self._store.store_mitigation_action(action)
        return action

    def get_mitigation_actions(
        self, recommendation_id: str
    ) -> List[MitigationAction]:
        """Get mitigation actions for a recommendation."""
        return self._store.get_mitigation_actions_by_recommendation(
            recommendation_id
        )

    def make_risk_decision(
        self,
        context: str,
        risk_factors: Dict[str, float],
        decision: str,
        reasoning: str = "",
        confidence: float = 0.8,
        **kwargs: Any,
    ) -> RiskDecision:
        """Make a risk-based decision."""
        risk_decision = RiskDecision(
            context=context,
            risk_factors=risk_factors,
            decision=decision,
            reasoning=reasoning,
            confidence=confidence,
            **kwargs,
        )
        self._store.store_risk_decision(risk_decision)
        return risk_decision

    def get_risk_decisions(self) -> List[RiskDecision]:
        """Get all risk decisions."""
        return self._store.get_all_risk_decisions()

    def explain_decision(
        self,
        decision_id: str,
        explanation: str,
        factors: List[Dict[str, Any]],
        **kwargs: Any,
    ) -> ExplainabilityRecord:
        """Create explainability record for a decision."""
        record = ExplainabilityRecord(
            decision_id=decision_id,
            explanation=explanation,
            factors=factors,
            **kwargs,
        )
        self._store.store_explainability(record)
        return record

    def get_explanation(
        self, decision_id: str
    ) -> Optional[ExplainabilityRecord]:
        """Get explainability record for a decision."""
        return self._store.get_explainability(decision_id)

    def create_governance_decision(
        self,
        title: str,
        description: str,
        decision_type: DecisionType,
        rationale: str = "",
        **kwargs: Any,
    ) -> GovernanceDecision:
        """Create a governance decision."""
        decision = GovernanceDecision(
            title=title,
            description=description,
            decision_type=decision_type,
            rationale=rationale,
            **kwargs,
        )
        self._store.store_governance_decision(decision)
        return decision

    def get_governance_decisions(self) -> List[GovernanceDecision]:
        """Get all governance decisions."""
        return self._store.get_governance_decisions()

    def get_metrics(self) -> DecisionMetrics:
        """Get decision metrics."""
        recommendations = self._store.get_all_recommendations()
        type_counts: Dict[str, int] = {}
        priority_counts: Dict[str, int] = {}

        for rec in recommendations:
            type_counts[rec.decision_type.value] = (
                type_counts.get(rec.decision_type.value, 0) + 1
            )
            priority_counts[rec.priority.value] = (
                priority_counts.get(rec.priority.value, 0) + 1
            )

        top_recommendations = [
            {"id": r.recommendation_id, "title": r.title, "confidence": r.confidence}
            for r in sorted(
                recommendations, key=lambda x: x.confidence, reverse=True
            )[:10]
        ]

        return DecisionMetrics(
            total_decisions=len(recommendations),
            recommendations_generated=len([
                r for r in recommendations
                if r.status == DecisionStatus.RECOMMENDED
            ]),
            recommendations_approved=len([
                r for r in recommendations
                if r.status == DecisionStatus.APPROVED
            ]),
            average_confidence=sum(
                r.confidence for r in recommendations
            ) / max(len(recommendations), 1),
            decisions_by_type=type_counts,
            decisions_by_priority=priority_counts,
            top_recommendations=top_recommendations,
        )

    def clear(self) -> None:
        """Clear all data."""
        reset_decision_store()


_decision_service: Optional[DecisionService] = None


def get_decision_service() -> DecisionService:
    global _decision_service
    if _decision_service is None:
        _decision_service = DecisionService()
    return _decision_service


def reset_decision_service() -> None:
    global _decision_service
    _decision_service = None
    reset_decision_store()
