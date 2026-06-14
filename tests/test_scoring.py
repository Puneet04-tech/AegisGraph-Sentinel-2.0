"""Unit tests for the centralized Risk Scoring Engine refactor."""

import math
import os
from unittest.mock import patch

import pytest 

if os.getenv("RUN_TORCH_TESTS", "").lower() != "true":
    pytest.skip("PyTorch tests require RUN_TORCH_TESTS=true", allow_module_level=True)

# Handle optional torch dependency for inference.risk_scorer
try:
    from src.inference.risk_scorer import compute_risk_score as inference_compute_risk_score
    from src.scoring import (
        EdgeCaseHandler, 
        RiskScorer,
        ScoreCalculator, 
        ThresholdConfig,
    )
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

pytestmark = pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch not installed")


def test_normalize_score_bounds_and_scaling():
    assert ScoreCalculator.normalize_score(0.5) == 0.5
    assert ScoreCalculator.normalize_score(-1.0) == 0.0
    assert ScoreCalculator.normalize_score(2.0) == 1.0
    assert ScoreCalculator.normalize_score(5.0, min_value=0.0, max_value=10.0) == 0.5


def test_threshold_behavior_decision_mapping():
    config = ThresholdConfig({"allow": 0.0, "review": 0.4, "block": 0.8})
    assert config.decision_for_score(0.0) == "ALLOW"
    assert config.decision_for_score(0.39) == "ALLOW"
    assert config.decision_for_score(0.4) == "REVIEW"
    assert config.decision_for_score(0.79) == "REVIEW"
    assert config.decision_for_score(0.8) == "BLOCK"
    assert config.decision_for_score(1.0) == "BLOCK"
    assert config.get_threshold("review") == 0.4
    assert config.get_threshold("block") == 0.8 


def test_compute_confidence_is_bounded_and_deterministic():
    breakdown = {"graph": 0.8, "velocity": 0.6, "temporal": 0.4}
    confidence = ScoreCalculator.compute_confidence(0.75, breakdown)
    assert 0.0 <= confidence <= 1.0
    assert confidence == ScoreCalculator.compute_confidence(0.75, breakdown)


def test_aggregate_scores_respects_weights_and_bounds():
    components = {"graph": 0.6, "velocity": 0.4}
    weights = {"graph": 0.8, "velocity": 0.2}
    score = ScoreCalculator.aggregate_scores(components, weights)
    assert math.isclose(score, 0.56, rel_tol=1e-9)
    assert 0.0 <= score <= 1.0

    score_default = ScoreCalculator.aggregate_scores(components, None)
    assert score_default == 0.5

def test_risk_scorer_assessments_are_valid():
    scorer = RiskScorer()
    assessment = scorer.assess({"graph_risk": 0.95, "velocity_risk": 0.1, "temporal_risk": 0.2})
    assert 0.0 <= assessment.overall_score <= 1.0
    assert 0.0 <= assessment.confidence <= 1.0
    assert assessment.decision in {"ALLOW", "REVIEW", "BLOCK"}


def test_inference_risk_scorer_function_returns_expected_schema():
    transaction = {
        "source_account": "user_test",
        "target_account": "merchant_test",
        "amount": 2500.0,
        "timestamp": "2024-01-01T03:00:00Z",
    }

    result = inference_compute_risk_score(transaction=transaction, graph_data=None, biometrics=None)

    assert isinstance(result, dict)
    assert set(result.keys()) >= {"risk_score", "decision", "confidence", "breakdown"}
    assert 0.0 <= result["risk_score"] <= 1.0
    assert 0.0 <= result["confidence"] <= 1.0
    assert result["decision"] in {"ALLOW", "REVIEW", "BLOCK"}
    assert isinstance(result["breakdown"], dict)
    assert set(result["breakdown"].keys()) == {"graph", "velocity", "behavior", "entropy"}


def test_nan_and_infinite_component_values_are_handled():
    components = {"graph": float("nan"), "velocity": float("inf")}
    score = ScoreCalculator.aggregate_scores(components, {"graph": 0.5, "velocity": 0.5})
    assert score == 0.0


def test_extreme_weight_values_are_normalized_and_clamped():
    components = {"graph": 1.0, "velocity": 1.0}
    weights = {"graph": 10.0, "velocity": -5.0}
    score = ScoreCalculator.aggregate_scores(components, weights)
    assert 0.0 <= score <= 1.0


def test_missing_components_fallback_to_neutral_values():
    scorer = RiskScorer(component_weights={"graph": 0.6, "velocity": 0.4})
    assessment = scorer.assess({"graph": 0.8})
    assert assessment.breakdown.components["velocity"] == 0.5
    assert 0.0 <= assessment.overall_score <= 1.0


def test_threshold_config_valid_overrides_are_applied():
    config = ThresholdConfig({"allow": 0.1, "review": 0.5, "block": 0.85})
    assert config.get_threshold("allow") == 0.1
    assert config.get_threshold("review") == 0.5
    assert config.get_threshold("block") == 0.85
    assert config.decision_for_score(0.49) == "ALLOW"
    assert config.decision_for_score(0.5) == "REVIEW"
    assert config.decision_for_score(0.85) == "BLOCK"


def test_threshold_config_boundaries_are_non_overlapping():
    config = ThresholdConfig({"allow": 0.5, "review": 0.7, "block": 0.9})
   
    assert config.decision_for_score(0.49) == "ALLOW"
    assert config.decision_for_score(0.50) == "ALLOW"
    assert config.decision_for_score(0.69) == "ALLOW"
    assert config.decision_for_score(0.70) == "REVIEW"
    assert config.decision_for_score(0.89) == "REVIEW"
    assert config.decision_for_score(0.90) == "BLOCK"


def test_threshold_config_invalid_values_fallback_to_defaults():
    config = ThresholdConfig({"allow": 1.0, "review": 0.5, "block": 0.4})
    assert config.get_threshold("allow") == 0.0
    assert config.get_threshold("review") == 0.6
    assert config.get_threshold("block") == 0.9


def test_threshold_config_rejects_equal_boundaries():
    config = ThresholdConfig({"allow": 0.5, "review": 0.5, "block": 0.9})

    assert config.get_threshold("allow") == 0.0
    assert config.get_threshold("review") == 0.6
    assert config.get_threshold("block") == 0.9


def test_legacy_inference_wrapper_matches_central_assessment_for_neutral_inputs(monkeypatch):
    import src.api.main as api_main

    blank_state = api_main.AppState()
    blank_state.graph_loaded = False
    blank_state.transaction_graph = None
    blank_state.account_profiles = {}
    blank_state.config = {}

    monkeypatch.setattr("src.api.main.state", blank_state)

    def fail_load_thresholds(*args, **kwargs):
        raise Exception("no thresholds")

    monkeypatch.setattr("src.inference.risk_scorer.load_thresholds", fail_load_thresholds)

    transaction = {
        "source_account": "neutral_user",
        "target_account": "neutral_merchant",
        "amount": 100.0, 
        "timestamp": "2025-01-01T12:00:00Z",
    }

    result = inference_compute_risk_score(transaction=transaction, graph_data=None, biometrics=None)
    expected_scorer = RiskScorer(
        threshold_config=ThresholdConfig({"allow": 0.5, "review": 0.7, "block": 0.9}),
        component_weights={"graph": 0.5, "velocity": 0.2, "behavior": 0.2, "entropy": 0.1},
    )
    expected = expected_scorer.assess({"graph": 0.0, "velocity": 0.0, "behavior": 0.0, "entropy": 0.0})

    assert result["risk_score"] == expected.overall_score
    assert result["decision"] == expected.decision
    assert result["confidence"] == expected.confidence
    assert result["breakdown"] == {"graph": 0.0, "velocity": 0.0, "behavior": 0.0, "entropy": 0.0}


def test_legacy_inference_wrapper_uses_overridden_thresholds(monkeypatch):
    import src.api.main as api_main

    blank_state = api_main.AppState()
    blank_state.graph_loaded = False
    blank_state.transaction_graph = None
    blank_state.account_profiles = {}
    blank_state.config = {}

    monkeypatch.setattr("src.api.main.state", blank_state)

    def return_thresholds(*args, **kwargs):
        return {"risk_scoring": {"allow": 0.05, "review": 0.4, "block": 0.8}}

    monkeypatch.setattr("src.inference.risk_scorer.load_thresholds", return_thresholds)

    transaction = {
        "source_account": "neutral_user",
        "target_account": "neutral_merchant",
        "amount": 100.0,
        "timestamp": "2025-01-01T12:00:00Z",
    }

    result = inference_compute_risk_score(transaction=transaction, graph_data=None, biometrics=None)
    assert result["decision"] == "ALLOW"
    assert result["risk_score"] == 0.0


def test_score_calculator_equal_weights_for_zero_sum_weights():
    components = {"graph": 0.4, "velocity": 0.6}
    weights = {"graph": 0.0, "velocity": 0.0}
    assert ScoreCalculator.aggregate_scores(components, weights) == 0.5


def test_confidence_stability_for_small_input_variations():
    baseline = ScoreCalculator.compute_confidence(0.5, {"graph": 0.5, "velocity": 0.5})
    nearby = ScoreCalculator.compute_confidence(0.5001, {"graph": 0.5, "velocity": 0.5})
    assert abs(baseline - nearby) <= 0.05


def test_confidence_stability_with_extreme_breakdown_values():
    assert math.isclose(ScoreCalculator.compute_confidence(1.0, {"graph": 1.0, "velocity": 1.0}), 1.0, rel_tol=1e-9)
    assert math.isclose(ScoreCalculator.compute_confidence(0.0, {"graph": 0.0, "velocity": 0.0}), 0.1, rel_tol=1e-9)
    assert 0.0 <= ScoreCalculator.compute_confidence(0.5, {"graph": 1.0, "velocity": 0.0}) <= 1.0

