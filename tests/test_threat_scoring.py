"""
Unit tests for ThreatScoringEngine in src/threat_hunting/threat_scoring.py
"""

import pytest
from unittest.mock import MagicMock

from src.threat_hunting.threat_scoring import ThreatScoringEngine
from src.threat_hunting.models import ThreatSeverity
from src.threat_hunting.store import ThreatHuntingStore, get_store


@pytest.fixture(autouse=True)
def reset_store():
    store = get_store()
    store.reset()
    yield
    store.reset()


@pytest.fixture
def mock_store():
    return MagicMock(spec=ThreatHuntingStore)


class TestThreatScoringEngine:
    """Tests for ThreatScoringEngine.calculate_score."""

    def test_zero_scores_yields_low_severity(self, mock_store):
        """All-zero input scores should produce LOW severity."""
        engine = ThreatScoringEngine(store=mock_store)
        result = engine.calculate_score(
            entity_id="user-zero",
            entity_type="user",
            behavior_score=0.0,
            campaign_score=0.0,
            graph_score=0.0,
            intel_score=0.0,
        )
        assert result.severity == ThreatSeverity.LOW
        assert 0.0 <= result.score <= 0.25

    def test_all_max_scores_yields_critical_severity(self, mock_store):
        """All-maximum scores should produce CRITICAL severity."""
        engine = ThreatScoringEngine(store=mock_store)
        result = engine.calculate_score(
            entity_id="user-max",
            entity_type="user",
            behavior_score=1.0,
            campaign_score=1.0,
            graph_score=1.0,
            intel_score=1.0,
        )
        assert result.severity == ThreatSeverity.CRITICAL
        assert result.score == 1.0

    def test_behavioral_only_score(self, mock_store):
        """Only behavioral component set should weight correctly."""
        engine = ThreatScoringEngine(store=mock_store)
        result = engine.calculate_score(
            entity_id="user-behave",
            entity_type="user",
            behavior_score=1.0,
        )
        expected_score = 1.0 * 0.35
        assert abs(result.score - expected_score) < 1e-9

    def test_input_clamping_behavioral(self, mock_store):
        """Behavior score above 1.0 is clamped to 1.0."""
        engine = ThreatScoringEngine(store=mock_store)
        result = engine.calculate_score(
            entity_id="user-clamp",
            behavior_score=2.0,
        )
        assert result.score <= 1.0

    def test_input_clamping_negative(self, mock_store):
        """Negative scores are clamped to 0.0."""
        engine = ThreatScoringEngine(store=mock_store)
        result = engine.calculate_score(
            entity_id="user-neg",
            behavior_score=-0.5,
        )
        assert result.score >= 0.0

    def test_severity_breakdown(self, mock_store):
        """Verify severity thresholds: LOW < 0.25, MEDIUM < 0.5, HIGH < 0.75, CRITICAL >= 0.75.

        Inputs are clamped to [0, 1] before weighting: score = sum(clamp(x) * weight).
        With only behavioral component (weight 0.35), max score is 0.35 -> MEDIUM.
        """
        engine = ThreatScoringEngine(store=mock_store)
        # LOW: zero score
        result = engine.calculate_score(entity_id="s-low", behavior_score=0.0)
        assert result.severity == ThreatSeverity.LOW
        # LOW boundary: 0.7 * 0.35 = 0.245 < 0.25
        result = engine.calculate_score(entity_id="s-low-bound", behavior_score=0.7)
        assert result.severity == ThreatSeverity.LOW
        # MEDIUM: 0.72 * 0.35 = 0.252 >= 0.25
        result = engine.calculate_score(entity_id="s-med-bound", behavior_score=0.72)
        assert result.severity == ThreatSeverity.MEDIUM
        # MEDIUM: 1.0 * 0.35 = 0.35 -> MEDIUM
        result = engine.calculate_score(entity_id="s-med", behavior_score=1.0)
        assert result.severity == ThreatSeverity.MEDIUM
        # CRITICAL: all max = 0.35 + 0.25 + 0.20 + 0.20 = 1.0 -> CRITICAL
        result = engine.calculate_score(
            entity_id="s-critical",
            behavior_score=1.0, campaign_score=1.0,
            graph_score=1.0, intel_score=1.0,
        )
        assert result.severity == ThreatSeverity.CRITICAL

    def test_breakdown_includes_all_components(self, mock_store):
        """The breakdown dict should include all four scoring components."""
        engine = ThreatScoringEngine(store=mock_store)
        result = engine.calculate_score(
            entity_id="user-breakdown",
            entity_type="device",
            behavior_score=0.5,
            campaign_score=0.5,
            graph_score=0.5,
            intel_score=0.5,
        )
        assert "behavioral" in result.breakdown
        assert "campaign" in result.breakdown
        assert "graph" in result.breakdown
        assert "intelligence" in result.breakdown
        assert result.breakdown["behavioral"] == 0.5

    def test_active_indicators_registered(self, mock_store):
        """Active indicator IDs are stored in the result."""
        engine = ThreatScoringEngine(store=mock_store)
        indicators = ["ind-1", "ind-2"]
        result = engine.calculate_score(
            entity_id="user-ind",
            active_indicators=indicators,
        )
        assert result.active_indicators == indicators

    def test_store_defaults_to_get_store(self):
        """No store passed uses the global get_store() instance."""
        store = get_store()
        store.reset()
        engine = ThreatScoringEngine()
        assert engine.store is store

    def test_entity_type_preserved(self, mock_store):
        """Entity type is stored in the result."""
        engine = ThreatScoringEngine(store=mock_store)
        result = engine.calculate_score(
            entity_id="user-type",
            entity_type="device",
        )
        assert result.entity_type == "device"
