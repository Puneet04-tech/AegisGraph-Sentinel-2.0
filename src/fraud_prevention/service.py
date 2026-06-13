"""Autonomous Fraud Prevention Network Service"""

from __future__ import annotations

from datetime import datetime, timezone  # noqa: F401
from typing import List, Optional

from .models import PreventionPolicy, FraudPattern, RiskScore, BlockRule, PreventionEvent, PreventionMetrics
from .store import get_fraud_prevention_store, FraudPreventionStore, reset_fraud_prevention_store


class FraudPreventionService:
    """Core fraud prevention service."""

    def __init__(self, store: Optional[FraudPreventionStore] = None):
        self._store = store or get_fraud_prevention_store()

    def create_policy(self, name: str, description: str, policy_type: str, action: str) -> PreventionPolicy:
        policy = PreventionPolicy(name=name, description=description, policy_type=policy_type, action=action)
        self._store.store_policy(policy)
        return policy

    def get_policy(self, policy_id: str) -> Optional[PreventionPolicy]:
        return self._store.get_policy(policy_id)

    def learn_pattern(self, name: str, pattern_type: str, indicators: List[str]) -> FraudPattern:
        pattern = FraudPattern(name=name, pattern_type=pattern_type, indicators=indicators)
        self._store.store_pattern(pattern)
        return pattern

    def calculate_risk(self, entity_id: str, factors: List[str]) -> RiskScore:
        score = RiskScore(entity_id=entity_id, score=0.5, factors=factors)
        self._store.store_score(score)
        return score

    def create_block_rule(self, name: str, pattern_id: str, threshold: float = 0.8) -> BlockRule:
        rule = BlockRule(name=name, pattern_id=pattern_id, threshold=threshold)
        self._store.store_rule(rule)
        return rule

    def prevent(self, event_type: str, entity_id: str, action: str) -> PreventionEvent:
        event = PreventionEvent(event_type=event_type, entity_id=entity_id, action_taken=action, outcome="PREVENTED")
        self._store.store_event(event)
        return event

    def get_metrics(self) -> PreventionMetrics:
        m = self._store.get_metrics()
        return PreventionMetrics(**m)


_fraud_prevention_service: Optional[FraudPreventionService] = None


def get_fraud_prevention_service() -> FraudPreventionService:
    global _fraud_prevention_service
    if _fraud_prevention_service is None:
        _fraud_prevention_service = FraudPreventionService()
    return _fraud_prevention_service


def reset_fraud_prevention_service() -> None:
    global _fraud_prevention_service
    _fraud_prevention_service = None
    reset_fraud_prevention_store()
