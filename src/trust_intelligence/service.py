"""Trust Intelligence Platform Service"""

from __future__ import annotations

from typing import Dict, Optional

from .models import TrustScore, IdentityVerification, ReputationIndex, TrustPolicy, TrustMetrics
from .store import get_trust_intelligence_store, TrustIntelligenceStore, reset_trust_intelligence_store


class TrustIntelligenceService:
    """Core trust intelligence service."""

    def __init__(self, store: Optional[TrustIntelligenceStore] = None):
        self._store = store or get_trust_intelligence_store()

    def calculate_trust(self, entity_id: str, factors: Dict[str, float]) -> TrustScore:
        score = TrustScore(entity_id=entity_id, trust_score=0.8, confidence=0.9, factors=factors)
        self._store.store_score(score)
        return score

    def get_trust(self, score_id: str) -> Optional[TrustScore]:
        return self._store.get_score(score_id)

    def verify_identity(self, entity_id: str, level: str = "BASIC") -> IdentityVerification:
        v = IdentityVerification(entity_id=entity_id, verification_level=level)
        self._store.store_verification(v)
        return v

    def update_reputation(self, entity_id: str, score: float) -> ReputationIndex:
        r = ReputationIndex(entity_id=entity_id, score=score)
        self._store.store_reputation(r)
        return r

    def create_policy(self, name: str, min_score: float, action: str) -> TrustPolicy:
        p = TrustPolicy(name=name, min_trust_score=min_score, action=action)
        self._store.store_policy(p)
        return p

    def get_metrics(self) -> TrustMetrics:
        m = self._store.get_metrics()
        return TrustMetrics(**m)


_trust_intelligence_service: Optional[TrustIntelligenceService] = None


def get_trust_intelligence_service() -> TrustIntelligenceService:
    global _trust_intelligence_service
    if _trust_intelligence_service is None:
        _trust_intelligence_service = TrustIntelligenceService()
    return _trust_intelligence_service


def reset_trust_intelligence_service() -> None:
    global _trust_intelligence_service
    _trust_intelligence_service = None
    reset_trust_intelligence_store()
