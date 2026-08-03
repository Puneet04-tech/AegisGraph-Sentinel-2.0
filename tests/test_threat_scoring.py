"""Dedicated unit tests for src/threat_hunting/threat_scoring.py.

``ThreatScoringEngine.calculate_score`` was only exercised indirectly.
These tests pin the weighted-sum math, input clamping, severity-mapping
boundaries and the in-memory store integration.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from src.threat_hunting.models import ThreatScore, ThreatSeverity
from src.threat_hunting.store import ThreatHuntingStore
from src.threat_hunting.threat_scoring import ThreatScoringEngine


@pytest.fixture
def store() -> ThreatHuntingStore:
    return ThreatHuntingStore()


@pytest.fixture
def engine(store: ThreatHuntingStore) -> ThreatScoringEngine:
    return ThreatScoringEngine(store=store)


def test_all_zero_components_score_zero_and_low(engine):
    score = engine.calculate_score("entity-1")
    assert score.score == 0.0
    assert score.severity == ThreatSeverity.LOW
    assert score.entity_id == "entity-1"
    assert score.breakdown == {
        "behavioral": 0.0,
        "campaign": 0.0,
        "graph": 0.0,
        "intelligence": 0.0,
    }


def test_all_max_components_score_one_and_critical(engine):
    score = engine.calculate_score(
        "entity-1",
        behavior_score=1.0,
        campaign_score=1.0,
        graph_score=1.0,
        intel_score=1.0,
    )
    assert score.score == 1.0
    assert score.severity == ThreatSeverity.CRITICAL


def test_weighted_sum_is_exact_for_partial_inputs(engine):
    # 0.35*1.0 + 0.25*0.5 + 0.20*0 + 0.20*0 == 0.475
    score = engine.calculate_score(
        "entity-1", behavior_score=1.0, campaign_score=0.5
    )
    assert score.score == pytest.approx(0.475)
    assert score.severity == ThreatSeverity.MEDIUM


def test_inputs_above_one_are_clamped(engine):
    score = engine.calculate_score("entity-1", behavior_score=2.0)
    assert score.score == pytest.approx(0.35)


def test_inputs_below_zero_are_clamped(engine):
    score = engine.calculate_score("entity-1", behavior_score=-1.0)
    assert score.score == 0.0


def test_severity_boundary_low_to_medium():
    store = ThreatHuntingStore()
    engine = ThreatScoringEngine(store=store)
    # score just below 0.25 -> LOW
    low = engine.calculate_score("e", behavior_score=0.3)  # 0.105
    assert low.severity == ThreatSeverity.LOW
    # score exactly 0.25 -> MEDIUM (>= 0.25)
    mid = engine.calculate_score("e", behavior_score=0.25 / 0.35)  # 0.25
    assert mid.score == pytest.approx(0.25)
    assert mid.severity == ThreatSeverity.MEDIUM


def test_severity_boundary_medium_to_high():
    engine = ThreatScoringEngine(store=ThreatHuntingStore())
    # 0.35 + 0.25*0.6 == 0.5 -> HIGH (>= 0.5)
    score = engine.calculate_score("e", behavior_score=1.0, campaign_score=0.6)
    assert score.score == pytest.approx(0.5)
    assert score.severity == ThreatSeverity.HIGH


def test_severity_boundary_high_to_critical():
    engine = ThreatScoringEngine(store=ThreatHuntingStore())
    # 0.35 + 0.25 + 0.20*0.75 == 0.75 -> CRITICAL (>= 0.75)
    score = engine.calculate_score(
        "e", behavior_score=1.0, campaign_score=1.0, graph_score=0.75
    )
    assert score.score == pytest.approx(0.75)
    assert score.severity == ThreatSeverity.CRITICAL


def test_active_indicators_default_empty():
    engine = ThreatScoringEngine(store=ThreatHuntingStore())
    score = engine.calculate_score("e")
    assert score.active_indicators == []


def test_active_indicators_preserved():
    engine = ThreatScoringEngine(store=ThreatHuntingStore())
    score = engine.calculate_score(
        "e", behavior_score=1.0, active_indicators=["ind-1", "ind-2"]
    )
    assert score.active_indicators == ["ind-1", "ind-2"]


def test_entity_type_defaults_to_user():
    engine = ThreatScoringEngine(store=ThreatHuntingStore())
    score = engine.calculate_score("e", behavior_score=1.0)
    assert score.entity_type == "user"
    assert score.entity_id == "e"


def test_custom_entity_type_is_preserved():
    engine = ThreatScoringEngine(store=ThreatHuntingStore())
    score = engine.calculate_score("e", entity_type="account", behavior_score=1.0)
    assert score.entity_type == "account"


def test_score_is_cached_in_store(engine, store):
    engine.calculate_score("e", behavior_score=1.0)
    cached = store.get_threat_score("e")
    assert cached is not None
    assert isinstance(cached, ThreatScore)
    assert cached.score == pytest.approx(0.35)


def test_calculated_at_is_valid_isoformat(engine):
    score = engine.calculate_score("e", behavior_score=1.0)
    # Should round-trip through fromisoformat.
    parsed = datetime.fromisoformat(score.calculated_at)
    assert parsed.tzinfo is not None


def test_weights_sum_to_one_for_normalised_score():
    engine = ThreatScoringEngine(store=ThreatHuntingStore())
    assert sum(engine.weights.values()) == pytest.approx(1.0)
