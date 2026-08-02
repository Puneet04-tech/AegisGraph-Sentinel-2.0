"""Dedicated unit tests for src/scoring/threshold_config.py.

The ``ThresholdConfig`` decision engine (default thresholds, merging of
custom thresholds, ordering validation that resets invalid configs, and
the ``ALLOW`` / ``REVIEW`` / ``BLOCK`` decision boundaries) previously had
no dedicated test module.  These tests pin the boundary semantics so the
fraud decision pipeline cannot regress silently.
"""

from __future__ import annotations

import math

import pytest

from src.scoring.threshold_config import (
    DEFAULT_RISK_THRESHOLDS,
    ThresholdConfig,
)
from src.scoring.edge_cases import EdgeCaseHandler


# ---------------------------------------------------------------------------
# Construction & defaults
# ---------------------------------------------------------------------------


def test_default_thresholds_match_reference():
    config = ThresholdConfig()
    assert config.thresholds == dict(DEFAULT_RISK_THRESHOLDS)


def test_default_thresholds_are_allow_below_review_below_block():
    config = ThresholdConfig()
    allow = config.thresholds["allow"]
    review = config.thresholds["review"]
    block = config.thresholds["block"]
    assert allow < review < block


def test_custom_thresholds_are_merged_with_defaults():
    config = ThresholdConfig({"review": 0.5})
    assert config.thresholds["allow"] == 0.0
    assert config.thresholds["review"] == 0.5
    assert config.thresholds["block"] == 0.9


def test_custom_thresholds_preserve_unrelated_keys():
    config = ThresholdConfig({"review": 0.5, "custom_key": 0.42})
    # Only allow/review/block are validated, but user-supplied extras survive.
    assert config.thresholds["custom_key"] == 0.42


def test_thresholds_are_isolated_from_caller_mutation():
    overrides = {"review": 0.55}
    config = ThresholdConfig(overrides)
    overrides["review"] = 0.99  # mutate caller's dict
    assert config.thresholds["review"] == 0.55


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_invalid_ordering_resets_to_defaults():
    # allow >= review violates 0 <= allow < review < block <= 1
    config = ThresholdConfig({"allow": 0.7, "review": 0.5, "block": 0.9})
    assert config.thresholds == dict(DEFAULT_RISK_THRESHOLDS)


def test_block_below_review_resets_to_defaults():
    config = ThresholdConfig({"allow": 0.0, "review": 0.6, "block": 0.4})
    assert config.thresholds == dict(DEFAULT_RISK_THRESHOLDS)


def test_block_at_one_is_valid():
    config = ThresholdConfig({"allow": 0.0, "review": 0.6, "block": 1.0})
    assert config.thresholds["block"] == 1.0


def test_allow_must_be_non_negative():
    config = ThresholdConfig({"allow": -0.5, "review": 0.6, "block": 0.9})
    # safe_score clamps -0.5 -> 0.0, so allow becomes 0.0 which is valid.
    assert config.thresholds["allow"] == 0.0
    assert config.thresholds["block"] == 0.9


def test_super_unit_block_clamps_and_remains_valid():
    # block=5.0 -> safe_score clamps to 1.0; ordering still valid -> kept.
    config = ThresholdConfig({"allow": 0.0, "review": 0.6, "block": 5.0})
    assert config.thresholds["block"] == 1.0
    assert config.thresholds["review"] == 0.6


def test_empty_overrides_use_defaults():
    config = ThresholdConfig({})
    assert config.thresholds == dict(DEFAULT_RISK_THRESHOLDS)


# ---------------------------------------------------------------------------
# get_threshold
# ---------------------------------------------------------------------------


def test_get_threshold_returns_configured_value():
    config = ThresholdConfig({"block": 0.8})
    assert config.get_threshold("block") == 0.8


def test_get_threshold_returns_default_for_missing_key():
    config = ThresholdConfig()
    assert config.get_threshold("nonexistent", default=123.0) == 123.0


def test_get_threshold_returns_none_by_default():
    config = ThresholdConfig()
    assert config.get_threshold("nonexistent") is None


# ---------------------------------------------------------------------------
# decision_for_score
# ---------------------------------------------------------------------------


def test_decision_allows_below_review():
    config = ThresholdConfig()
    assert config.decision_for_score(0.3) == "ALLOW"


def test_decision_reviews_at_or_above_review():
    config = ThresholdConfig()
    assert config.decision_for_score(0.6) == "REVIEW"
    assert config.decision_for_score(0.7) == "REVIEW"


def test_decision_blocks_at_or_above_block():
    config = ThresholdConfig()
    assert config.decision_for_score(0.9) == "BLOCK"
    assert config.decision_for_score(1.0) == "BLOCK"


def test_decision_boundary_review_threshold():
    config = ThresholdConfig({"review": 0.5, "block": 0.8})
    assert config.decision_for_score(0.49) == "ALLOW"
    assert config.decision_for_score(0.5) == "REVIEW"
    assert config.decision_for_score(0.79) == "REVIEW"
    assert config.decision_for_score(0.8) == "BLOCK"


def test_decision_nan_is_treated_as_zero_allow():
    config = ThresholdConfig()
    assert config.decision_for_score(float("nan")) == "ALLOW"


def test_decision_infinity_treated_as_zero_allow():
    # safe_score maps +/-inf to 0.0, so they resolve to ALLOW, not BLOCK.
    config = ThresholdConfig()
    assert config.decision_for_score(float("inf")) == "ALLOW"
    assert config.decision_for_score(float("-inf")) == "ALLOW"


def test_decision_above_one_clamps_to_block():
    config = ThresholdConfig()
    assert config.decision_for_score(2.0) == "BLOCK"


def test_decision_below_zero_clamps_to_allow():
    config = ThresholdConfig()
    assert config.decision_for_score(-0.5) == "ALLOW"


def test_decision_monotonic_as_score_increases():
    config = ThresholdConfig()
    scores = [0.0, 0.3, 0.6, 0.9, 1.0]
    decisions = [config.decision_for_score(s) for s in scores]
    rank = {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2}
    assert [rank[d] for d in decisions] == sorted(rank[d] for d in decisions)


def test_decision_non_string_score_falls_back_to_allow():
    config = ThresholdConfig()
    # safe_score returns 0.0 for non-numeric -> ALLOW
    assert config.decision_for_score(None) == "ALLOW"
    assert config.decision_for_score("high") == "ALLOW"


# ---------------------------------------------------------------------------
# from_dict classmethod
# ---------------------------------------------------------------------------


def test_from_dict_builds_config_with_merged_thresholds():
    config = ThresholdConfig.from_dict({"review": 0.7})
    assert isinstance(config, ThresholdConfig)
    assert config.thresholds["review"] == 0.7
    assert config.decision_for_score(0.8) == "REVIEW"


def test_from_dict_invalid_reverts_to_defaults():
    config = ThresholdConfig.from_dict({"allow": 0.9, "review": 0.5, "block": 0.6})
    assert config.thresholds == dict(DEFAULT_RISK_THRESHOLDS)
