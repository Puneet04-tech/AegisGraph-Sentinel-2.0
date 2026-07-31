"""Tests for Trust Intelligence Platform."""

import pytest

from src.trust_intelligence.models import TrustScore, IdentityVerification
from src.trust_intelligence.store import (
    TrustIntelligenceStore,
    get_trust_intelligence_store,
    reset_trust_intelligence_store,
)
from src.trust_intelligence.service import TrustIntelligenceService


class TestTrustIntelligenceModels:
    def test_create_trust_score(self):
        score = TrustScore(entity_id="e-001", trust_score=0.85)
        assert score.trust_score == 0.85

    def test_create_verification(self):
        v = IdentityVerification(entity_id="e-001", verification_level="ADVANCED")
        assert v.verification_level == "ADVANCED"


class TestTrustIntelligenceStore:
    def setup_method(self):
        reset_trust_intelligence_store()
        self.store = get_trust_intelligence_store()

    def test_store_score(self):
        score = TrustScore(entity_id="test", trust_score=0.9)
        self.store.store_score(score)
        assert self.store.get_score(score.score_id) is not None

    def test_get_metrics_empty(self):
        assert self.store.get_metrics() == {
            "total_entities": 0,
            "avg_trust_score": 0.0,
            "verified_entities": 0,
        }

    def test_get_metrics_averages_stored_scores(self):
        # Regression: avg_trust_score used to be a hardcoded 0.75 constant.
        self.store.store_score(TrustScore(entity_id="e1", trust_score=0.5))
        self.store.store_score(TrustScore(entity_id="e2", trust_score=1.0))
        self.store.store_verification(IdentityVerification(entity_id="e1"))

        metrics = self.store.get_metrics()
        assert metrics["total_entities"] == 2
        assert metrics["avg_trust_score"] == pytest.approx(0.75)
        assert metrics["verified_entities"] == 1

    def test_get_metrics_reflects_any_scores(self):
        self.store.store_score(TrustScore(entity_id="e1", trust_score=0.1))
        self.store.store_score(TrustScore(entity_id="e2", trust_score=0.3))
        self.store.store_score(TrustScore(entity_id="e3", trust_score=0.2))
        assert self.store.get_metrics()["avg_trust_score"] == pytest.approx(0.2)

    def test_store_and_get_reputation(self):
        from src.trust_intelligence.models import ReputationIndex

        reputation = ReputationIndex(entity_id="e1", score=0.9)
        assert self.store.store_reputation(reputation) is reputation
        assert self.store.get_reputation(reputation.index_id) is reputation

    def test_store_and_get_policy(self):
        from src.trust_intelligence.models import TrustPolicy

        policy = TrustPolicy(name="high-risk", min_trust_score=0.7, action="REVIEW")
        assert self.store.store_policy(policy) is policy
        assert self.store.get_policy(policy.policy_id) is policy


class TestTrustIntelligenceService:
    def setup_method(self):
        reset_trust_intelligence_store()
        self.service = TrustIntelligenceService()

    def test_calculate_trust(self):
        score = self.service.calculate_trust("entity-001", {"history": 0.9, "behavior": 0.8})
        assert score.score_id is not None

    def test_verify_identity(self):
        v = self.service.verify_identity("entity-001", "ENHANCED")
        assert v.verification_id is not None

    def test_update_reputation(self):
        r = self.service.update_reputation("entity-001", 0.95)
        assert r.index_id is not None

    def test_create_policy(self):
        p = self.service.create_policy("High Trust", 0.8, "ALLOW")
        assert p.policy_id is not None

    def test_get_metrics(self):
        m = self.service.get_metrics()
        assert m.total_entities >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
