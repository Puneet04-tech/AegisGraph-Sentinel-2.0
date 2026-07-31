"""Unit tests for src.trust_intelligence.store."""

import pytest

from src.trust_intelligence.models import (
    IdentityVerification,
    ReputationIndex,
    TrustPolicy,
    TrustScore,
)
from src.trust_intelligence.store import (
    TrustIntelligenceStore,
    get_trust_intelligence_store,
    reset_trust_intelligence_store,
)


def test_store_and_get_score() -> None:
    store = TrustIntelligenceStore()
    score = TrustScore(entity_id="e1", trust_score=0.8)
    assert store.store_score(score) is score
    assert store.get_score(score.score_id) is score
    assert store.get_score("missing") is None


def test_store_and_get_verification() -> None:
    store = TrustIntelligenceStore()
    verification = IdentityVerification(entity_id="e1", verification_level="HIGH")
    assert store.store_verification(verification) is verification
    assert store.get_verification(verification.verification_id) is verification


def test_store_and_get_reputation() -> None:
    store = TrustIntelligenceStore()
    reputation = ReputationIndex(entity_id="e1", score=0.9)
    assert store.store_reputation(reputation) is reputation
    assert store.get_reputation(reputation.index_id) is reputation


def test_store_and_get_policy() -> None:
    store = TrustIntelligenceStore()
    policy = TrustPolicy(name="high-risk", min_trust_score=0.7, action="REVIEW")
    assert store.store_policy(policy) is policy
    assert store.get_policy(policy.policy_id) is policy


def test_get_metrics_empty() -> None:
    store = TrustIntelligenceStore()
    metrics = store.get_metrics()
    assert metrics["total_entities"] == 0
    assert metrics["avg_trust_score"] == 0.0
    assert metrics["verified_entities"] == 0


def test_get_metrics_averages_stored_scores() -> None:
    # Regression: avg_trust_score used to be a hardcoded constant.
    store = TrustIntelligenceStore()
    store.store_score(TrustScore(entity_id="e1", trust_score=0.5))
    store.store_score(TrustScore(entity_id="e2", trust_score=1.0))
    store.store_verification(IdentityVerification(entity_id="e1"))

    metrics = store.get_metrics()
    assert metrics["total_entities"] == 2
    assert metrics["avg_trust_score"] == 0.75
    assert metrics["verified_entities"] == 1


def test_get_metrics_handles_any_scores() -> None:
    store = TrustIntelligenceStore()
    store.store_score(TrustScore(entity_id="e1", trust_score=0.1))
    store.store_score(TrustScore(entity_id="e2", trust_score=0.3))
    store.store_score(TrustScore(entity_id="e3", trust_score=0.2))
    assert store.get_metrics()["avg_trust_score"] == pytest.approx(0.2)


def test_get_trust_intelligence_store_singleton_and_reset() -> None:
    reset_trust_intelligence_store()
    first = get_trust_intelligence_store()
    second = get_trust_intelligence_store()
    assert first is second
    reset_trust_intelligence_store()
    assert get_trust_intelligence_store() is not first
