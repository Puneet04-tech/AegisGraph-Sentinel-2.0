"""Unit tests for the AI governance engines.

Covers ``src.ai_governance.governance_engine``: drift detection,
bias detection, explainability, and the aggregate governance engine
(audit logging + compliance status).
"""

from __future__ import annotations

import random

import pytest

from src.ai_governance.governance_engine import (
    AIGovernanceEngine,
    BiasDetectionEngine,
    DriftDetectionEngine,
    ExplainabilityEngine,
)
from src.ai_governance.models import BiasMetric, DriftType
from src.ai_governance.registry import ModelRegistry


@pytest.fixture
def registry() -> ModelRegistry:
    return ModelRegistry()


@pytest.fixture
def model_id(registry: ModelRegistry) -> str:
    return registry.register_model(
        name="htgnn",
        version="1.0.0",
        model_type="graph",
        owner="fraud-team",
    )


# ---------------------------------------------------------------------------
# DriftDetectionEngine
# ---------------------------------------------------------------------------


class TestDriftDetection:
    def test_empty_inputs_yield_zero_score(self, registry, model_id):
        engine = DriftDetectionEngine(registry)

        drift = engine.detect_drift(model_id, [], [])

        assert drift.drift_score == 0.0
        assert drift.severity == "LOW"

    def test_identical_key_sets_produce_low_score(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        current = [{"amount": 100.0, "velocity": 3.0}]
        baseline = [{"amount": 50.0, "velocity": 1.0}]

        drift = engine.detect_drift(model_id, current, baseline)

        assert 0.1 <= drift.drift_score <= 0.3
        assert drift.severity == "LOW"
        assert drift.drift_type == DriftType.DATA_DRIFT

    def test_missing_keys_raise_drift_score(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        current = [{"amount": 100.0}]
        baseline = [{"amount": 50.0, "velocity": 1.0, "risk": 0.5}]

        drift = engine.detect_drift(model_id, current, baseline)

        assert drift.drift_score > 0.3

    def test_severity_escalates_with_score(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        current = [{"a": 1.0}]
        baseline = [{"a": 1.0, "b": 1.0, "c": 1.0, "d": 1.0, "e": 1.0}]

        drift = engine.detect_drift(model_id, current, baseline)

        assert drift.severity in {"HIGH", "CRITICAL"}

    def test_drift_history_is_recorded(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        engine.detect_drift(model_id, [{"a": 1.0}], [{"a": 1.0, "b": 2.0}])

        assert len(engine.get_drift_history(model_id)) == 1

    def test_get_drift_history_unknown_model_returns_empty(self, registry):
        engine = DriftDetectionEngine(registry)
        assert engine.get_drift_history("unknown") == []

    def test_get_latest_drift_returns_most_recent(self, registry, model_id):
        engine = DriftDetectionEngine(registry)
        first = engine.detect_drift(model_id, [{"a": 1.0}], [{"a": 1.0, "b": 2.0}])
        second = engine.detect_drift(model_id, [{"a": 1.0}], [{"a": 1.0, "b": 2.0}])

        assert engine.get_latest_drift(model_id).drift_id == second.drift_id
        assert engine.get_latest_drift(model_id) is not first

    def test_get_latest_drift_unknown_model_returns_none(self, registry):
        engine = DriftDetectionEngine(registry)
        assert engine.get_latest_drift("unknown") is None


# ---------------------------------------------------------------------------
# BiasDetectionEngine
# ---------------------------------------------------------------------------


class TestBiasDetection:
    def test_one_report_per_metric(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        reports = engine.detect_bias(
            model_id,
            predictions=[{"risk": 0.7}],
            protected_attributes=["gender", "age"],
        )

        assert len(reports) == len(list(BiasMetric))
        assert {r.metric for r in reports} == set(BiasMetric)

    def test_score_is_bounded_to_unit_interval(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        reports = engine.detect_bias(model_id, [], ["gender"])

        assert all(0.0 <= r.score <= 1.0 for r in reports)
        assert all(r.threshold == 0.8 for r in reports)

    def test_fairness_flag_matches_threshold(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        reports = engine.detect_bias(model_id, [], ["gender"])

        for report in reports:
            assert report.is_fair == (report.score >= report.threshold)

    def test_reports_are_persisted(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        engine.detect_bias(model_id, [], ["gender"])

        assert len(engine.get_bias_reports(model_id)) == len(list(BiasMetric))

    def test_get_latest_reports_dedupes_per_metric(self, registry, model_id):
        engine = BiasDetectionEngine(registry)
        first = engine.detect_bias(model_id, [], ["gender"])
        second = engine.detect_bias(model_id, [], ["age"])

        latest = engine.get_latest_reports(model_id)

        assert len(latest) == len(list(BiasMetric))
        assert latest[0].metric == second[0].metric

    def test_get_bias_reports_unknown_model_returns_empty(self, registry):
        engine = BiasDetectionEngine(registry)
        assert engine.get_bias_reports("unknown") == []


# ---------------------------------------------------------------------------
# ExplainabilityEngine
# ---------------------------------------------------------------------------


class TestExplainability:
    def test_feature_importance_normalised(self, registry, model_id):
        engine = ExplainabilityEngine(registry)
        explanation = engine.explain_prediction(
            model_id, "pred-1", {"amount": 100.0, "velocity": 300.0}
        )

        assert explanation.prediction_id == "pred-1"
        assert explanation.explanation_method == "SHAP"
        assert sum(explanation.feature_importance.values()) == pytest.approx(1.0)

    def test_non_numeric_features_get_fallback_weight(self, registry, model_id):
        engine = ExplainabilityEngine(registry)
        explanation = engine.explain_prediction(
            model_id, "pred-2", {"amount": 100.0, "merchant": "acme"}
        )

        assert explanation.feature_importance["merchant"] == 0.5
        assert explanation.feature_importance["amount"] == pytest.approx(100.0 / 101.0)

    def test_explanations_are_stored(self, registry, model_id):
        engine = ExplainabilityEngine(registry)
        explanation = engine.explain_prediction(model_id, "pred-1", {"amount": 1.0})

        assert engine.get_explanation(explanation.explanation_id) is explanation

    def test_get_explanation_unknown_returns_none(self, registry):
        engine = ExplainabilityEngine(registry)
        assert engine.get_explanation("missing") is None


# ---------------------------------------------------------------------------
# AIGovernanceEngine
# ---------------------------------------------------------------------------


class TestGovernanceEngine:
    def test_log_action_persists_audit_record(self, registry, model_id):
        engine = AIGovernanceEngine(registry)
        record = engine.log_action(model_id, "deploy", "analyst", {"env": "prod"})

        assert record.model_id == model_id
        assert record.action == "deploy"
        assert record.user == "analyst"
        assert record.details == {"env": "prod"}
        assert record in engine.audit_log

    def test_get_audit_log_filters_by_model(self, registry, model_id):
        engine = AIGovernanceEngine(registry)
        other_id = registry.register_model("other", "1.0", "llm")
        engine.log_action(model_id, "train", "alice")
        engine.log_action(other_id, "deploy", "bob")

        entries = engine.get_audit_log(model_id=model_id)
        assert len(entries) == 1
        assert entries[0].model_id == model_id

    def test_get_audit_log_respects_limit(self, registry, model_id):
        engine = AIGovernanceEngine(registry)
        for i in range(5):
            engine.log_action(model_id, f"action-{i}", "user")

        assert len(engine.get_audit_log(model_id=model_id, limit=2)) == 2

    def test_compliance_status_unknown_model(self, registry):
        engine = AIGovernanceEngine(registry)
        assert engine.get_compliance_status("missing") == {"error": "Model not found"}

    def test_compliance_status_clean_model(self, registry, model_id):
        engine = AIGovernanceEngine(registry)

        status = engine.get_compliance_status(model_id)

        assert status["model_id"] == model_id
        assert status["compliance_score"] == 1.0
        assert status["drift_detected"] is False
        assert status["bias_issues"] == 0
        assert status["requires_review"] is False

    def test_compliance_score_drops_with_high_drift(self, registry, model_id):
        engine = AIGovernanceEngine(registry)
        drift = engine.drift_engine.detect_drift(
            model_id, [{"a": 1.0}], [{"a": 1.0, "b": 2.0, "c": 3.0, "d": 4.0}]
        )
        drift.severity = "HIGH"

        status = engine.get_compliance_status(model_id)

        assert status["compliance_score"] == pytest.approx(0.7)
        assert status["drift_detected"] is True
        assert status["drift_severity"] == "HIGH"
        assert status["requires_review"] is False

    def test_compliance_score_never_goes_below_zero(self, registry, model_id):
        engine = AIGovernanceEngine(registry)
        drift = engine.drift_engine.detect_drift(
            model_id, [{"a": 1.0}], [{"a": 1.0, "b": 2.0, "c": 3.0, "d": 4.0}]
        )
        drift.severity = "CRITICAL"
        # Force every bias metric unfair to accumulate penalties.
        random.seed(0)
        engine.bias_engine.detect_bias(model_id, [], ["gender", "age"])

        status = engine.get_compliance_status(model_id)
        assert status["compliance_score"] >= 0.0
