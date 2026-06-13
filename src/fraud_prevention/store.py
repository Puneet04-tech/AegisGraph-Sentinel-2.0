"""Autonomous Fraud Prevention Network Store"""

from __future__ import annotations

from threading import Lock
from typing import Any, Dict, List, Optional

from .models import PreventionPolicy, FraudPattern, RiskScore, BlockRule, PreventionEvent


class FraudPreventionStore:
    """Thread-safe storage."""

    def __init__(self):
        self._lock = Lock()
        self._policies: Dict[str, PreventionPolicy] = {}
        self._patterns: Dict[str, FraudPattern] = {}
        self._scores: Dict[str, RiskScore] = {}
        self._rules: Dict[str, BlockRule] = {}
        self._events: Dict[str, PreventionEvent] = {}

    def store_policy(self, p: PreventionPolicy) -> PreventionPolicy:
        with self._lock:
            self._policies[p.policy_id] = p
        return p

    def get_policy(self, policy_id: str) -> Optional[PreventionPolicy]:
        return self._policies.get(policy_id)

    def get_all_policies(self) -> List[PreventionPolicy]:
        return list(self._policies.values())

    def store_pattern(self, p: FraudPattern) -> FraudPattern:
        with self._lock:
            self._patterns[p.pattern_id] = p
        return p

    def get_pattern(self, pattern_id: str) -> Optional[FraudPattern]:
        return self._patterns.get(pattern_id)

    def store_score(self, s: RiskScore) -> RiskScore:
        with self._lock:
            self._scores[s.score_id] = s
        return s

    def get_score(self, score_id: str) -> Optional[RiskScore]:
        return self._scores.get(score_id)

    def store_rule(self, r: BlockRule) -> BlockRule:
        with self._lock:
            self._rules[r.rule_id] = r
        return r

    def get_rule(self, rule_id: str) -> Optional[BlockRule]:
        return self._rules.get(rule_id)

    def store_event(self, e: PreventionEvent) -> PreventionEvent:
        with self._lock:
            self._events[e.event_id] = e
        return e

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_prevented": len([e for e in self._events.values() if e.outcome == "PREVENTED"]),
            "patterns_learned": len(self._patterns),
            "policies_active": len([p for p in self._policies.values() if p.enabled]),
        }


_fraud_prevention_store: Optional[FraudPreventionStore] = None
_store_lock = Lock()


def get_fraud_prevention_store() -> FraudPreventionStore:
    global _fraud_prevention_store
    with _store_lock:
        if _fraud_prevention_store is None:
            _fraud_prevention_store = FraudPreventionStore()
        return _fraud_prevention_store


def reset_fraud_prevention_store() -> None:
    global _fraud_prevention_store
    with _store_lock:
        _fraud_prevention_store = FraudPreventionStore()
