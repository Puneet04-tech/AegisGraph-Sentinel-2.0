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

    def test_get_metrics_single_score(self):
        self.store.store_score(TrustScore(entity_id="e1", trust_score=0.5))
        metrics = self.store.get_metrics()
        assert metrics["total_entities"] == 1
        assert metrics["avg_trust_score"] == pytest.approx(0.5)

    def test_get_metrics_rounds_average_to_four_decimals(self):
        # (0.33 + 0.33 + 0.34) / 3 = 0.3333... -> rounded to 4 decimals
        self.store.store_score(TrustScore(entity_id="e1", trust_score=0.33))
        self.store.store_score(TrustScore(entity_id="e2", trust_score=0.33))
        self.store.store_score(TrustScore(entity_id="e3", trust_score=0.34))
        assert self.store.get_metrics()["avg_trust_score"] == 0.3333

    def test_verified_entities_count_verifications_independently(self):
        self.store.store_verification(IdentityVerification(entity_id="e1"))
        self.store.store_verification(IdentityVerification(entity_id="e2"))
        self.store.store_verification(IdentityVerification(entity_id="e3"))
        metrics = self.store.get_metrics()
        assert metrics["total_entities"] == 0
        assert metrics["verified_entities"] == 3

    def test_reset_clears_all_state(self):
        self.store.store_score(TrustScore(entity_id="e1", trust_score=0.9))
        self.store.store_verification(IdentityVerification(entity_id="e1"))
        reset_trust_intelligence_store()
        fresh = get_trust_intelligence_store()
        assert fresh.get_metrics() == {
            "total_entities": 0,
            "avg_trust_score": 0.0,
            "verified_entities": 0,
        }

    def test_trust_score_defaults(self):
        score = TrustScore(entity_id="e1")
        assert score.trust_score == 0.5
        assert score.confidence == 0.0
        assert score.factors == {}

    def test_identity_verification_defaults(self):
        v = IdentityVerification(entity_id="e1")
        assert v.verification_level == "BASIC"
        assert v.expires_at is None

    def test_reputation_defaults_and_history(self):
        from src.trust_intelligence.models import ReputationIndex

        r = ReputationIndex(entity_id="e1")
        assert r.score == 0.0
        assert r.history == []

    def test_trust_policy_defaults(self):
        from src.trust_intelligence.models import TrustPolicy

        policy = TrustPolicy(name="high-risk", min_trust_score=0.7, action="REVIEW")
        assert policy.min_trust_score == 0.7
        assert policy.enabled is True

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
        self.store = get_trust_intelligence_store()
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

    def test_calculate_trust_stores_factors(self):
        factors = {"history": 0.9, "behavior": 0.8}
        score = self.service.calculate_trust("entity-001", factors)
        assert score.entity_id == "entity-001"
        assert score.trust_score == 0.8
        assert score.confidence == 0.9
        assert score.factors == factors
        assert self.service.get_trust(score.score_id) is score

    def test_verify_identity_level_roundtrip(self):
        v = self.service.verify_identity("entity-001", "ENHANCED")
        assert v.verification_level == "ENHANCED"
        assert self.store.get_verification(v.verification_id) is v

    def test_update_reputation_roundtrip(self):
        r = self.service.update_reputation("entity-001", 0.95)
        assert self.store.get_reputation(r.index_id) is r

    def test_create_policy_roundtrip(self):
        p = self.service.create_policy("High Trust", 0.8, "ALLOW")
        assert self.store.get_policy(p.policy_id) is p

    def test_get_metrics_reflects_service_actions(self):
        self.service.calculate_trust("entity-001", {"history": 0.9})
        self.service.verify_identity("entity-001", "ADVANCED")
        m = self.service.get_metrics()
        assert m.total_entities == 1
        assert m.avg_trust_score == pytest.approx(0.8)
        assert m.verified_entities == 1
        assert m.high_risk_entities == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
