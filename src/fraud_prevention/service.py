"""Autonomous Fraud Prevention Service"""
from __future__ import annotations
from typing import Any, Dict, Optional
from .models import FraudAlert, PreventionRule, BlockedTransaction, FraudMetrics
from .store import get_fraud_prevention_store, FraudPreventionStore


class FraudPreventionService:
    """Core fraud prevention service."""

    def __init__(self, store: Optional[FraudPreventionStore] = None):
        self._store = store or get_fraud_prevention_store()

    def create_alert(self, transaction_id: str, risk_score: float, reason: str) -> FraudAlert:
        a = FraudAlert(transaction_id=transaction_id, risk_score=risk_score, reason=reason)
        return self._store.store_alert(a)

    def get_alert(self, alert_id: str) -> Optional[FraudAlert]:
        return self._store.get_alert(alert_id)

    def create_rule(self, name: str, condition: Dict[str, Any], action: str) -> PreventionRule:
        r = PreventionRule(name=name, condition=condition, action=action)
        return self._store.store_rule(r)

    def block_transaction(self, transaction_id: str, reason: str) -> BlockedTransaction:
        b = BlockedTransaction(transaction_id=transaction_id, reason=reason)
        return self._store.store_block(b)

    def get_metrics(self) -> FraudMetrics:
        m = self._store.get_metrics()
        return FraudMetrics(**m)


_service: Optional[FraudPreventionService] = None


def get_fraud_prevention_service() -> FraudPreventionService:
    global _service
    if _service is None:
        _service = FraudPreventionService()
    return _service
