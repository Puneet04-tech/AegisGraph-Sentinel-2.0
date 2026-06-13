"""Tests for Trust Intelligence Platform"""

import pytest

from src.trust_intelligence.models import TrustScore, IdentityVerification
from src.trust_intelligence.store import get_trust_intelligence_store, reset_trust_intelligence_store
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
