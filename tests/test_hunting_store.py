"""Dedicated unit tests for src/threat_hunting/store.py.

``ThreatHuntingStore`` is the thread-safe in-memory backbone for the hunting
subsystem (hunts, results, profiles, campaigns, indicators, correlations,
scores and history) but has no dedicated unit coverage.  These tests pin the
full CRUD surface, LRU eviction semantics and stats counters.
"""

import pytest

from src.threat_hunting.store import ThreatHuntingStore
from src.threat_hunting.models import (
    BehaviorProfile,
    HuntResult,
    HuntState,
    ThreatCampaign,
    ThreatCorrelation,
    ThreatHunt,
    ThreatIndicator,
    ThreatScore,
)


@pytest.fixture
def store() -> ThreatHuntingStore:
    return ThreatHuntingStore()


def test_hunt_crud_round_trip(store):
    hunt = store.add_hunt(ThreatHunt(name="hunt-1"))
    assert store.get_hunt(hunt.hunt_id) is hunt
    assert store.list_hunts() == [hunt]
    assert store.stats["hunts_started"] == 1


def test_update_hunt_state(store):
    hunt = store.add_hunt(ThreatHunt(name="hunt-1"))
    updated = store.update_hunt_state(hunt.hunt_id, state=HuntState.COMPLETED, findings_count=3)
    assert updated.state == HuntState.COMPLETED
    assert updated.findings_count == 3
    assert store.update_hunt_state("missing", state=HuntState.COMPLETED) is None


def test_results_scoped_by_hunt(store):
    store.add_result(HuntResult(hunt_id="h1", matched_entity_id="e1", threat_score=0.5))
    store.add_result(HuntResult(hunt_id="h1", matched_entity_id="e2", threat_score=0.8))
    results = store.get_results_for_hunt("h1")
    assert len(results) == 2
    assert store.get_results_for_hunt("missing") == []
    assert store.stats["results_recorded"] == 2


def test_profile_set_and_get(store):
    profile = store.set_profile(BehaviorProfile(entity_id="user-1"))
    assert store.get_profile("user-1") is profile
    assert store.get_profile("missing") is None


def test_campaign_set_and_list(store):
    campaign = store.set_campaign(ThreatCampaign(name="linked"))
    assert store.get_campaign(campaign.campaign_id) is campaign
    assert store.list_campaigns() == [campaign]


def test_indicator_registration(store):
    indicator = store.register_indicator(ThreatIndicator(value="10.0.0.1"))
    assert store.get_indicator(indicator.indicator_id) is indicator
    assert store.list_indicators() == [indicator]
    assert store.stats["indicators_registered"] == 1


def test_correlation_add_and_list(store):
    correlation = store.add_correlation(ThreatCorrelation(name="corr"))
    assert store.list_correlations() == [correlation]


def test_score_lru_evicts_oldest_unused(store):
    store = ThreatHuntingStore(cache_size=2)
    store.set_threat_score("a", ThreatScore(entity_id="a", score=0.1))
    store.set_threat_score("b", ThreatScore(entity_id="b", score=0.2))
    assert store.get_threat_score("a").score == 0.1
    store.set_threat_score("c", ThreatScore(entity_id="c", score=0.3))
    assert store.get_threat_score("b") is None
    assert store.get_threat_score("a") is not None
    assert store.get_threat_score("c") is not None


def test_history_truncated_to_max(store):
    store.max_history = 3
    for i in range(5):
        store.record_history("action", {"i": i})
    assert len(store.history) == 3
    assert store.history[-1]["details"] == {"i": 4}


def test_get_stats_counts(store):
    stats = store.get_stats()
    assert stats["hunts_count"] == 0
    assert stats["indicators_count"] == 0
    assert "stats_counters" in stats
    store.add_hunt(ThreatHunt(name="h"))
    assert store.get_stats()["hunts_count"] == 1


def test_reset_clears_records(store):
    store.add_hunt(ThreatHunt(name="h"))
    store.set_threat_score("a", ThreatScore(entity_id="a", score=0.9))
    store.record_history("action", {})
    store.reset()
    assert store.list_hunts() == []
    assert store.history == []
    assert store.stats["hunts_started"] == 0
