"""Autonomous Fraud Prevention Store"""
from __future__ import annotations
from threading import Lock
from typing import Any, Dict, Optional
from .models import FraudAlert, PreventionRule, BlockedTransaction


class FraudPreventionStore:
    """Thread-safe storage."""

    def __init__(self):
        self._lock = Lock()
        self._alerts: Dict[str, FraudAlert] = {}
        self._rules: Dict[str, PreventionRule] = {}
        self._blocks: Dict[str, BlockedTransaction] = {}

    def store_alert(self, a: FraudAlert) -> FraudAlert:
        with self._lock:
            self._alerts[a.alert_id] = a
        return a

    def get_alert(self, alert_id: str) -> Optional[FraudAlert]:
        return self._alerts.get(alert_id)

    def store_rule(self, r: PreventionRule) -> PreventionRule:
        with self._lock:
            self._rules[r.rule_id] = r
        return r

    def get_rule(self, rule_id: str) -> Optional[PreventionRule]:
        return self._rules.get(rule_id)

    def store_block(self, b: BlockedTransaction) -> BlockedTransaction:
        with self._lock:
            self._blocks[b.block_id] = b
        return b

    def get_block(self, block_id: str) -> Optional[BlockedTransaction]:
        return self._blocks.get(block_id)

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_alerts": len(self._alerts),
            "blocked_transactions": len(self._blocks),
            "active_rules": sum(1 for r in self._rules.values() if r.enabled),
        }


_store: Optional[FraudPreventionStore] = None


def get_fraud_prevention_store() -> FraudPreventionStore:
    global _store
    if _store is None:
        _store = FraudPreventionStore()
    return _store
