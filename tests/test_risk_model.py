import json

import pytest

from src.scoring.risk_model import RiskAssessment, RiskBreakdown
from src.runtime.failure_policy import (
    VALID_FAILURE_MODES,
    RuntimeFailurePolicy,
    normalize_failure_mode,
    should_allow_degraded,
    should_fail_fast,
)


class TestRiskBreakdown:
    def test_total_empty_components_is_zero(self):
        assert RiskBreakdown().total() == 0.0

    def test_total_sums_component_scores(self):
        breakdown = RiskBreakdown(components={"velocity": 0.35, "biometrics": 0.25})
        assert pytest.approx(breakdown.total()) == 0.6

    def test_total_with_floats_uses_approx(self):
        breakdown = RiskBreakdown(components={"a": 0.1, "b": 0.2, "c": 0.3})
        assert pytest.approx(breakdown.total()) == 0.6

    def test_to_dict_returns_copy_not_reference(self):
        components = {"velocity": 0.5}
        breakdown = RiskBreakdown(components=components)
        result = breakdown.to_dict()
        assert result == components
        assert result is not components

    def test_to_dict_round_trip_with_default_factory(self):
        breakdown = RiskBreakdown()
        assert breakdown.to_dict() == {}
        breakdown.components["honeypot"] = 0.1
        assert breakdown.to_dict() == {"honeypot": 0.1}


class TestRiskAssessment:
    def _make_assessment(self):
        breakdown = RiskBreakdown(components={"velocity": 0.4, "biometrics": 0.2})
        return RiskAssessment(
            overall_score=0.6,
            confidence=0.9,
            decision="high_risk",
            breakdown=breakdown,
            metadata={"source": "test"},
        )

    def test_to_dict_contains_all_fields(self):
        result = self._make_assessment().to_dict()
        assert result["overall_score"] == 0.6
        assert result["confidence"] == 0.9
        assert result["decision"] == "high_risk"
        assert result["breakdown"] == {"velocity": 0.4, "biometrics": 0.2}
        assert result["metadata"] == {"source": "test"}

    def test_to_dict_metadata_defaults_to_empty(self):
        assessment = RiskAssessment(
            overall_score=0.1,
            confidence=0.5,
            decision="low_risk",
            breakdown=RiskBreakdown(),
        )
        assert assessment.to_dict()["metadata"] == {}

    def test_to_dict_breakdown_is_flat_components(self):
        result = self._make_assessment().to_dict()
        assert result["breakdown"] == self._make_assessment().breakdown.to_dict()

    def test_to_json_round_trip_preserves_fields(self):
        assessment = self._make_assessment()
        payload = json.loads(assessment.to_json())
        assert payload["overall_score"] == 0.6
        assert payload["confidence"] == 0.9
        assert payload["decision"] == "high_risk"
        assert payload["breakdown"] == {"velocity": 0.4, "biometrics": 0.2}
        assert payload["metadata"] == {"source": "test"}

    def test_to_json_serializes_non_serializable_metadata(self):
        assessment = RiskAssessment(
            overall_score=0.0,
            confidence=1.0,
            decision="low_risk",
            breakdown=RiskBreakdown(),
            metadata={"object": object()},
        )
        payload = json.loads(assessment.to_json())
        assert payload["overall_score"] == 0.0
        assert payload["confidence"] == 1.0

    def test_decision_and_components_are_preserved(self):
        assessment = RiskAssessment(
            overall_score=0.85,
            confidence=0.92,
            decision="high_risk",
            breakdown=RiskBreakdown(components={"velocity": 0.5, "honeypot": 0.35}),
            metadata={"case_id": "case-42"},
        )
        data = json.loads(assessment.to_json())
        assert data["decision"] == "high_risk"
        assert data["breakdown"] == {"velocity": 0.5, "honeypot": 0.35}
        assert pytest.approx(sum(data["breakdown"].values())) == data["overall_score"]


class TestNormalizeFailureMode:
    def test_none_defaults_to_degraded(self):
        assert normalize_failure_mode(None) == "degraded"

    def test_valid_modes_passthrough(self):
        for mode in VALID_FAILURE_MODES:
            assert normalize_failure_mode(mode) == mode

    def test_normalizes_case_and_whitespace(self):
        assert normalize_failure_mode("  FAIL_FAST  ") == "fail_fast"
        assert normalize_failure_mode("Degraded") == "degraded"

    def test_invalid_mode_raises_value_error(self):
        with pytest.raises(ValueError, match="failure_mode"):
            normalize_failure_mode("explode")


class TestShouldFailFast:
    def test_fail_fast_is_true(self):
        assert should_fail_fast("fail_fast") is True

    def test_other_modes_are_false(self):
        assert should_fail_fast("degraded") is False
        assert should_fail_fast("maintenance") is False

    def test_degraded_allowance(self):
        assert should_allow_degraded("degraded") is True
        assert should_allow_degraded("maintenance") is True
        assert should_allow_degraded("fail_fast") is False


class TestRuntimeFailurePolicy:
    def test_default_mode_is_degraded(self):
        policy = RuntimeFailurePolicy()
        assert policy.mode == "degraded"

    def test_fail_fast_properties(self):
        policy = RuntimeFailurePolicy(mode="fail_fast")
        assert policy.is_fail_fast is True
        assert policy.is_degraded is False
        assert policy.is_maintenance is False

    def test_degraded_properties(self):
        policy = RuntimeFailurePolicy(mode="degraded")
        assert policy.is_fail_fast is False
        assert policy.is_degraded is True
        assert policy.is_maintenance is False

    def test_maintenance_properties(self):
        policy = RuntimeFailurePolicy(mode="maintenance")
        assert policy.is_fail_fast is False
        assert policy.is_degraded is False
        assert policy.is_maintenance is True

    def test_policy_is_frozen(self):
        policy = RuntimeFailurePolicy(mode="degraded")
        with pytest.raises(Exception):
            policy.mode = "fail_fast"
