"""
Autonomous Security Decision Engine Store - Thread-safe storage
"""

from __future__ import annotations

from threading import Lock
from typing import Dict, List, Optional

from .models import (
    SecurityRecommendation,
    MitigationAction,
    RiskDecision,
    ExplainabilityRecord,
    GovernanceDecision,
    DecisionType,
    DecisionPriority,
    DecisionStatus,
)


class DecisionStore:
    """Thread-safe storage for decision data."""

    def __init__(self):
        self._lock = Lock()
        self._recommendations: Dict[str, SecurityRecommendation] = {}
        self._mitigation_actions: Dict[str, MitigationAction] = {}
        self._risk_decisions: Dict[str, RiskDecision] = {}
        self._explainability: Dict[str, ExplainabilityRecord] = {}
        self._governance_decisions: Dict[str, GovernanceDecision] = {}

    def store_recommendation(
        self, recommendation: SecurityRecommendation
    ) -> SecurityRecommendation:
        with self._lock:
            self._recommendations[recommendation.recommendation_id] = recommendation
        return recommendation

    def get_recommendation(
        self, recommendation_id: str
    ) -> Optional[SecurityRecommendation]:
        return self._recommendations.get(recommendation_id)

    def get_recommendations_by_type(
        self, decision_type: DecisionType
    ) -> List[SecurityRecommendation]:
        return [
            r for r in self._recommendations.values()
            if r.decision_type == decision_type
        ]

    def get_recommendations_by_priority(
        self, priority: DecisionPriority
    ) -> List[SecurityRecommendation]:
        return [
            r for r in self._recommendations.values()
            if r.priority == priority
        ]

    def get_recommendations_by_status(
        self, status: DecisionStatus
    ) -> List[SecurityRecommendation]:
        return [
            r for r in self._recommendations.values()
            if r.status == status
        ]

    def get_all_recommendations(self) -> List[SecurityRecommendation]:
        return list(self._recommendations.values())

    def store_mitigation_action(
        self, action: MitigationAction
    ) -> MitigationAction:
        with self._lock:
            self._mitigation_actions[action.action_id] = action
        return action

    def get_mitigation_actions_by_recommendation(
        self, recommendation_id: str
    ) -> List[MitigationAction]:
        return [
            a for a in self._mitigation_actions.values()
            if a.recommendation_id == recommendation_id
        ]

    def store_risk_decision(
        self, decision: RiskDecision
    ) -> RiskDecision:
        with self._lock:
            self._risk_decisions[decision.decision_id] = decision
        return decision

    def get_risk_decision(
        self, decision_id: str
    ) -> Optional[RiskDecision]:
        return self._risk_decisions.get(decision_id)

    def get_all_risk_decisions(self) -> List[RiskDecision]:
        return list(self._risk_decisions.values())

    def store_explainability(
        self, record: ExplainabilityRecord
    ) -> ExplainabilityRecord:
        with self._lock:
            self._explainability[record.record_id] = record
        return record

    def get_explainability(
        self, decision_id: str
    ) -> Optional[ExplainabilityRecord]:
        for record in self._explainability.values():
            if record.decision_id == decision_id:
                return record
        return None

    def store_governance_decision(
        self, decision: GovernanceDecision
    ) -> GovernanceDecision:
        with self._lock:
            self._governance_decisions[decision.decision_id] = decision
        return decision

    def get_governance_decisions(self) -> List[GovernanceDecision]:
        return list(self._governance_decisions.values())

    def get_metrics(self) -> Dict[str, any]:
        recommendations = list(self._recommendations.values())
        type_counts: Dict[str, int] = {}
        priority_counts: Dict[str, int] = {}

        for rec in recommendations:
            type_counts[rec.decision_type.value] = (
                type_counts.get(rec.decision_type.value, 0) + 1
            )
            priority_counts[rec.priority.value] = (
                priority_counts.get(rec.priority.value, 0) + 1
            )

        return {
            "total_recommendations": len(recommendations),
            "recommendations_by_type": type_counts,
            "recommendations_by_priority": priority_counts,
            "approved_recommendations": len([
                r for r in recommendations
                if r.status == DecisionStatus.APPROVED
            ]),
        }


_decision_store: Optional[DecisionStore] = None
_store_lock = Lock()


def get_decision_store() -> DecisionStore:
    global _decision_store
    with _store_lock:
        if _decision_store is None:
            _decision_store = DecisionStore()
        return _decision_store


def reset_decision_store() -> None:
    global _decision_store
    with _store_lock:
        _decision_store = DecisionStore()
