"""Trust Intelligence Platform Store"""

from __future__ import annotations

from threading import Lock
from typing import Any, Dict, Optional

from .models import TrustScore, IdentityVerification, ReputationIndex, TrustPolicy


class TrustIntelligenceStore:
    """Thread-safe storage."""

    def __init__(self):
        self._lock = Lock()
        self._scores: Dict[str, TrustScore] = {}
        self._verifications: Dict[str, IdentityVerification] = {}
        self._reputations: Dict[str, ReputationIndex] = {}
        self._policies: Dict[str, TrustPolicy] = {}

    def store_score(self, s: TrustScore) -> TrustScore:
        with self._lock:
            self._scores[s.score_id] = s
        return s

    def get_score(self, score_id: str) -> Optional[TrustScore]:
        return self._scores.get(score_id)

    def store_verification(self, v: IdentityVerification) -> IdentityVerification:
        with self._lock:
            self._verifications[v.verification_id] = v
        return v

    def get_verification(self, verification_id: str) -> Optional[IdentityVerification]:
        return self._verifications.get(verification_id)

    def store_reputation(self, r: ReputationIndex) -> ReputationIndex:
        with self._lock:
            self._reputations[r.index_id] = r
        return r

    def get_reputation(self, index_id: str) -> Optional[ReputationIndex]:
        return self._reputations.get(index_id)

    def store_policy(self, p: TrustPolicy) -> TrustPolicy:
        with self._lock:
            self._policies[p.policy_id] = p
        return p

    def get_policy(self, policy_id: str) -> Optional[TrustPolicy]:
        return self._policies.get(policy_id)

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_entities": len(self._scores),
            "avg_trust_score": 0.75,
            "verified_entities": len(self._verifications),
        }


_trust_intelligence_store: Optional[TrustIntelligenceStore] = None
_store_lock = Lock()


def get_trust_intelligence_store() -> TrustIntelligenceStore:
    global _trust_intelligence_store
    with _store_lock:
        if _trust_intelligence_store is None:
            _trust_intelligence_store = TrustIntelligenceStore()
        return _trust_intelligence_store


def reset_trust_intelligence_store() -> None:
    global _trust_intelligence_store
    with _store_lock:
        _trust_intelligence_store = TrustIntelligenceStore()
