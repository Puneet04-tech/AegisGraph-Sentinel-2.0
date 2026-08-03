"""Dedicated unit tests for src/threat_hunting/hunting_engine.py.

``ThreatHuntingEngine`` was untested.  These tests pin hunt lifecycle
(transitions PENDING -> RUNNING -> COMPLETED), score-threshold filtering,
indicator-type filtering, the missing-hunt guard and the failure path that
records a FAILED state.
"""

from __future__ import annotations

import pytest

from src.threat_hunting.hunting_engine import ThreatHuntingEngine
from src.threat_hunting.models import (
    HuntState,
    IndicatorType,
    ThreatIndicator,
    ThreatScore,
)
from src.threat_hunting.store import ThreatHuntingStore


@pytest.fixture
def store() -> ThreatHuntingStore:
    return ThreatHuntingStore()


@pytest.fixture
def engine(store: ThreatHuntingStore) -> ThreatHuntingEngine:
    return ThreatHuntingEngine(store=store)


def _seed_score(store, entity_id, score, indicators=None, entity_type="user"):
    store.set_threat_score(
        entity_id,
        ThreatScore(
            entity_id=entity_id,
            entity_type=entity_type,
            score=score,
            active_indicators=indicators or [],
        ),
    )


# ---------------------------------------------------------------------------
# Hunt lifecycle
# ---------------------------------------------------------------------------


def test_start_hunt_completes_and_records_results(engine, store):
    _seed_score(store, "ent-1", 0.7)
    _seed_score(store, "ent-2", 0.8)

    hunt = engine.start_hunt("weekend-baseline", "weekly hunt", {})
    assert hunt.state == HuntState.COMPLETED
    assert hunt.started_at is not None
    assert hunt.completed_at is not None
    assert hunt.findings_count == 2

    results = store.get_results_for_hunt(hunt.hunt_id)
    assert len(results) == 2
    assert {r.matched_entity_id for r in results} == {"ent-1", "ent-2"}


def test_start_hunt_with_no_scores_completes_with_zero_findings(engine, store):
    hunt = engine.start_hunt("empty", "no scores", {})
    assert hunt.state == HuntState.COMPLETED
    assert hunt.findings_count == 0
    assert store.get_results_for_hunt(hunt.hunt_id) == []


def test_default_criteria_matches_all_scores(engine, store):
    _seed_score(store, "a", 0.1)
    _seed_score(store, "b", 0.9)
    hunt = engine.start_hunt("h", "d", {})
    assert hunt.findings_count == 2


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


def test_score_threshold_filters_entities(engine, store):
    _seed_score(store, "low", 0.3)
    _seed_score(store, "high", 0.8)
    hunt = engine.start_hunt("h", "d", {"min_threat_score": 0.5})
    assert hunt.findings_count == 1
    results = store.get_results_for_hunt(hunt.hunt_id)
    assert results[0].matched_entity_id == "high"


def test_indicator_type_filter(engine, store):
    ip_ind = ThreatIndicator(indicator_type=IndicatorType.IP, value="1.2.3.4")
    domain_ind = ThreatIndicator(indicator_type=IndicatorType.DOMAIN, value="x.com")
    store.register_indicator(ip_ind)
    store.register_indicator(domain_ind)
    _seed_score(store, "ip-entity", 0.9, indicators=[ip_ind.indicator_id])
    _seed_score(store, "domain-entity", 0.9, indicators=[domain_ind.indicator_id])

    hunt = engine.start_hunt("h", "d", {"indicator_types": ["IP"]})
    results = store.get_results_for_hunt(hunt.hunt_id)
    assert {r.matched_entity_id for r in results} == {"ip-entity"}


def test_indicator_type_filter_excludes_unlinked_scores(engine, store):
    _seed_score(store, "orphan", 0.9)  # no active_indicators
    hunt = engine.start_hunt("h", "d", {"indicator_types": ["IP"]})
    assert hunt.findings_count == 0


# ---------------------------------------------------------------------------
# Missing hunt & failure path
# ---------------------------------------------------------------------------


def test_execute_hunt_missing_id_returns_none(engine):
    assert engine.execute_hunt("does-not-exist") is None


def test_failure_path_marks_hunt_failed(store):
    class BrokenStore(ThreatHuntingStore):
        def get_threat_score(self, entity_id):  # noqa: D401
            raise RuntimeError("boom")

        def update_hunt_state(self, hunt_id, **kwargs):
            # Record the state we would have written.
            super().update_hunt_state(hunt_id, **kwargs)

    broken = BrokenStore()
    engine = ThreatHuntingEngine(store=broken)
    from src.threat_hunting.models import ThreatHunt, HuntState
    broken.add_hunt(ThreatHunt(name="h", description="d"))
    # Seed a score so execute_hunt() iterates scores and hits the override
    # that raises, exercising the failure path.
    broken.set_threat_score("ent-1", ThreatScore(entity_id="ent-1", score=0.5))
    hunt_id = broken.list_hunts()[0].hunt_id
    engine.execute_hunt(hunt_id)
    hunt = broken.get_hunt(hunt_id)
    assert hunt.state == HuntState.FAILED
    assert hunt.error_message is not None
    assert "boom" in hunt.error_message


# ---------------------------------------------------------------------------
# Result detail
# ---------------------------------------------------------------------------


def test_result_details_contain_severity_and_breakdown(engine, store):
    _seed_score(store, "ent", 0.9)
    hunt = engine.start_hunt("h", "d", {})
    (result,) = store.get_results_for_hunt(hunt.hunt_id)
    assert result.threat_score == pytest.approx(0.9)
    assert "severity" in result.details
    assert "breakdown" in result.details
