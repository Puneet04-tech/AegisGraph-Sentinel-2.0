"""Unit tests for the AI governance subsystem.

Covers ``src.ai_governance``: ``ModelRegistry``, ``DriftDetectionEngine``,
``BiasDetectionEngine``, ``ExplainabilityEngine``, ``AIGovernanceEngine``
and the supporting data models.
"""

from __future__ import annotations

import pytest

from src.ai_governance.governance_engine import (
    AIGovernanceEngine,
    BiasDetectionEngine,
    DriftDetectionEngine,
    ExplainabilityEngine,
)
from src.ai_governance.models import (
    AuditRecord,
    BiasMetric,
    BiasReport,
    DriftType,
    Model,
    ModelDrift,
    ModelExplanation,
    ModelRisk,
    ModelStatus,
)
from src.ai_governance.registry import ModelRegistry


@pytest.fixture
def registry() -> ModelRegistry:
    return ModelRegistry()


def _model(model_id: str = "m1", name: str = "FraudNet", version: str = "1.0") -> Model:
    return Model(
        model_id=model_id,
        name=name,
        version=version,
        model_type="classifier",
        framework="pytorch",
        owner="ml-team",
    )


def _register(registry: ModelRegistry, name: str = "FraudNet", version: str = "1.0") -> str:
    return registry.register_model(
        name=name,
        version=version,
        model_type="classifier",
        framework="pytorch",
        owner="ml-team",
    )


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_enum_values(self):
        assert ModelStatus.PRODUCTION.value == "PRODUCTION"
        assert ModelRisk.CRITICAL.value == "CRITICAL"
        assert BiasMetric.DEMOGRAPHIC_PARITY.value == "DEMOGRAPHIC_PARITY"
        assert DriftType.DATA_DRIFT.value == "DATA_DRIFT"

    def test_model_to_dict(self):
        model = _model()
        data = model.to_dict()
        assert data["model_id"] == "m1"
        assert data["status"] == "DEVELOPMENT"
        assert data["risk_level"] == "MEDIUM"

    def test_model_drift_to_dict(self):
        drift = ModelDrift(
            drift_id="d1", model_id="m1", drift_type=DriftType.CONCEPT_DRIFT,
            drift_score=0.9, severity="HIGH",
        )
        data = drift.to_dict()
        assert data["drift_type"] == "CONCEPT_DRIFT"
        assert data["severity"] == "HIGH"

    def test_bias_report_to_dict(self):
        report = BiasReport(
            report_id="r1", model_id="m1", metric=BiasMetric.CALIBRATION,
            score=0.5, threshold=0.8, is_fair=False, affected_groups=["age"],
        )
        data = report.to_dict()
        assert data["metric"] == "CALIBRATION"
        assert data["is_fair"] is False
        assert data["affected_groups"] == ["age"]

    def test_explanation_and_audit_to_dict(self):
        explanation = ModelExplanation(
            explanation_id="e1", model_id="m1", prediction_id="p1",
            feature_importance={"f": 1.0}, explanation_method="SHAP", confidence=0.9,
        )
        assert explanation.to_dict()["explanation_method"] == "SHAP"

        audit = AuditRecord(audit_id="a1", model_id="m1", action="deploy", user="admin")
        assert audit.to_dict()["action"] == "deploy"


# ---------------------------------------------------------------------------
# ModelRegistry
# ---------------------------------------------------------------------------


class TestModelRegistry:
    def test_register_and_get(self, registry):
        model_id = _register(registry)

        model = registry.get_model(model_id)
        assert model is not None
        assert model.name == "FraudNet"
        assert model.status == ModelStatus.DEVELOPMENT
        assert registry.get_model("missing") is None

    def test_get_by_name_latest_and_version(self, registry):
        v1 = _register(registry, version="1.0")
        v2 = _register(registry, version="2.0")

        assert registry.get_model_by_name("FraudNet").model_id == v2
        assert registry.get_model_by_name("FraudNet", version="1.0").model_id == v1
        assert registry.get_model_by_name("FraudNet", version="9.9") is None
        assert registry.get_model_by_name("Unknown") is None

    def test_update_model(self, registry):
        model_id = _register(registry)

        assert registry.update_model(model_id, status=ModelStatus.PRODUCTION, metrics={"auc": 0.9}) is True

        model = registry.get_model(model_id)
        assert model.status == ModelStatus.PRODUCTION
        assert model.deployed_at is not None
        assert model.metrics["auc"] == 0.9

    def test_update_missing_model_returns_false(self, registry):
        assert registry.update_model("missing", status=ModelStatus.PRODUCTION) is False

    def test_deprecate_model(self, registry):
        model_id = _register(registry)

        assert registry.deprecate_model(model_id) is True
        assert registry.get_model(model_id).status == ModelStatus.DEPRECATED
        assert registry.deprecate_model("missing") is False

    def test_list_models_with_filters(self, registry):
        _register(registry, name="A", version="1.0")
        _register(registry, name="B", version="1.0")

        registry.update_model(registry.get_model_by_name("B").model_id, status=ModelStatus.PRODUCTION)

        assert len(registry.list_models()) == 2
        assert len(registry.list_models(status=ModelStatus.PRODUCTION)) == 1
        assert len(registry.list_models(status=ModelStatus.DEPRECATED)) == 0

    def test_versions_and_production(self, registry):
        _register(registry, version="1.0")
        prod_id = _register(registry, version="2.0")
        registry.update_model(prod_id, status=ModelStatus.PRODUCTION)

        assert len(registry.get_model_versions("FraudNet")) == 2
        assert [m.model_id for m in registry.get_production_models()] == [prod_id]

    def test_registry_stats(self, registry):
        _register(registry)
        prod_id = _register(registry, name="Other", version="1.0")
        registry.update_model(prod_id, status=ModelStatus.PRODUCTION)

        stats = registry.get_registry_stats()
        assert stats["total_models"] == 2
        assert stats["total_unique_names"] == 2
        assert stats["production_count"] == 1
        assert stats["by_status"]["DEVELOPMENT"] == 1


# ---------------------------------------------------------------------------
# DriftDetectionEngine
# ---------------------------------------------------------------------------


class TestDriftDetection:
    def test_drift_score_empty_data(self, registry):
        engine = DriftDetectionEngine(registry=registry)
        assert engine._calculate_drift_score([], []) == 0.0
        assert engine._calculate_drift_score([{"a": 1}], []) == 0.0

    def test_drift_score_matching_keys(self, registry):
        # Issue #3198: this used to monkeypatch random.uniform and assert
        # the score equalled whatever constant was injected -- i.e. it
        # tested that the engine faithfully echoed a random number, not
        # that it measured anything. Now exercises the real PSI
        # computation: two datasets with matching keys and near-identical
        # distributions register a small, real, deterministic score.
        engine = DriftDetectionEngine(registry=registry)
        baseline = [{"a": 40.0 + i, "b": 1.0 + 0.1 * i} for i in range(20)]
        current = [{"a": 41.0 + i, "b": 1.0 + 0.1 * i} for i in range(20)]

        score = engine._calculate_drift_score(current, baseline)

        assert score == pytest.approx(0.21972245773362187)
        # Same inputs called again -> byte-identical (the regression this
        # issue asks for; previously every call re-rolled the dice).
        assert engine._calculate_drift_score(current, baseline) == score

    def test_drift_score_differing_keys_capped(self, registry):
        # Issue #3198: previously asserted only `0.0 < score <= 1.0`
        # against an injected random value. A key-set mismatch is now
        # defined as maximum drift (1.0), not a partial number computed
        # only over the overlapping keys -- see `_analyze_drift`'s
        # schema-mismatch handling.
        engine = DriftDetectionEngine(registry=registry)

        score = engine._calculate_drift_score(
            [{"a": 1, "b": 2, "c": 3}], [{"a": 1, "d": 4, "e": 5, "f": 6}]
        )
        assert score == 1.0

    def test_severity_classification(self, registry):
        # Issue #3198: previously monkeypatched random.uniform to force
        # each severity bucket. Now drives the real bucket boundaries with
        # hand-verified fixtures (a uniform 0..199 baseline shifted by a
        # known amount), computed once against this implementation and
        # pinned here so a regression shows up as a changed assertion.
        engine = DriftDetectionEngine(registry=registry)
        model_id = _register(registry)
        baseline = [{"a": float(i)} for i in range(200)]

        for shift, expected in [(1, "LOW"), (15, "MEDIUM"), (17, "HIGH"), (19, "CRITICAL")]:
            current = [{"a": float(i) + shift} for i in range(200)]
            drift = engine.detect_drift(model_id, current, baseline)
            assert drift.severity == expected, f"shift {shift}: score {drift.drift_score}"

    def test_drift_history_and_latest(self, registry):
        engine = DriftDetectionEngine(registry=registry)
        model_id = _register(registry)
        current = [{"a": 1.0 + i} for i in range(10)]
        baseline = [{"a": 1.0 + i} for i in range(10)]

        engine.detect_drift(model_id, current, baseline)
        engine.detect_drift(model_id, current, baseline)

        assert len(engine.get_drift_history(model_id)) == 2
        assert engine.get_latest_drift(model_id) == engine.get_drift_history(model_id)[-1]
        assert engine.get_drift_history("missing") == []
        assert engine.get_latest_drift("missing") is None


# ---------------------------------------------------------------------------
# BiasDetectionEngine
# ---------------------------------------------------------------------------


def _balanced_predictions() -> list:
    """8 records across 2 protected attributes (age, gender) x 2 groups
    each, prediction == label in every record and every combination's
    positive rate is exactly 0.5 -- demographic parity, disparate impact,
    equalized odds and calibration are all perfectly fair on this input."""
    combos = [("young", "M"), ("young", "F"), ("old", "M"), ("old", "F")]
    predictions = []
    for age, gender in combos:
        predictions.append({"prediction": 1, "label": 1, "age": age, "gender": gender})
        predictions.append({"prediction": 0, "label": 0, "age": age, "gender": gender})
    return predictions


class TestBiasDetection:
    def test_one_report_per_metric(self, registry):
        # Issue #3198: previously monkeypatched random.uniform to force a
        # "fair" score with no relationship to the input data. Now uses a
        # hand-constructed, genuinely balanced dataset (see
        # `_balanced_predictions`) so every metric is both real and fair.
        engine = BiasDetectionEngine(registry=registry)

        reports = engine.detect_bias("m1", _balanced_predictions(), ["age", "gender"])

        assert len(reports) == len(list(BiasMetric))
        assert {r.metric for r in reports} == set(BiasMetric)
        assert all(r.status == "computed" for r in reports)
        assert all(r.is_fair for r in reports)

    def test_unfair_report_attributes_groups(self, registry):
        # Issue #3198: previously monkeypatched random.uniform/random.random
        # to force an "unfair" verdict and a coin-flip choice of affected
        # groups with no relationship to the input. Now uses a genuinely
        # skewed dataset (age/gender fully confounded with the outcome).
        engine = BiasDetectionEngine(registry=registry)
        predictions = (
            [{"prediction": 1, "label": 1, "age": "young", "gender": "M"} for _ in range(4)]
            + [{"prediction": 0, "label": 0, "age": "old", "gender": "F"} for _ in range(4)]
        )

        reports = engine.detect_bias("m1", predictions, ["age", "gender"])

        unfair = [r for r in reports if r.status == "computed" and not r.is_fair]
        assert unfair, "expected at least one metric to detect the skew"
        for report in unfair:
            assert report.affected_groups
            for entry in report.affected_groups:
                attr, _, group = entry.partition(":")
                assert attr in ("age", "gender")
                assert group

    def test_report_retrieval(self, registry):
        engine = BiasDetectionEngine(registry=registry)

        engine.detect_bias("m1", _balanced_predictions(), ["age"])
        engine.detect_bias("m1", _balanced_predictions(), ["age"])

        assert len(engine.get_bias_reports("m1")) == 8
        assert len(engine.get_latest_reports("m1")) == len(list(BiasMetric))
        assert engine.get_bias_reports("missing") == []


# ---------------------------------------------------------------------------
# ExplainabilityEngine
# ---------------------------------------------------------------------------


class TestExplainability:
    def test_feature_importance_normalization(self, registry):
        engine = ExplainabilityEngine(registry=registry)

        importance = engine._calculate_feature_importance({"f1": 2.0, "f2": 2.0})

        assert importance["f1"] == 0.5
        assert importance["f2"] == 0.5

    def test_non_numeric_feature_fallback(self, registry):
        engine = ExplainabilityEngine(registry=registry)

        importance = engine._calculate_feature_importance({"f1": "x", "f2": "y"})

        assert importance["f1"] == 0.5
        assert importance["f2"] == 0.5

    def test_explain_prediction_and_lookup(self, registry, monkeypatch):
        engine = ExplainabilityEngine(registry=registry)
        monkeypatch.setattr("src.ai_governance.governance_engine.random.uniform", lambda a, b: 0.9)

        explanation = engine.explain_prediction("m1", "pred-1", {"amount": 1000, "risk": 0.5})

        assert explanation.explanation_method == "SHAP"
        assert explanation.confidence == 0.9
        assert "amount" in explanation.feature_importance
        assert engine.get_explanation(explanation.explanation_id) is explanation
        assert engine.get_explanation("missing") is None


# ---------------------------------------------------------------------------
# AIGovernanceEngine
# ---------------------------------------------------------------------------


class TestGovernanceEngine:
    def test_audit_logging_and_filters(self):
        engine = AIGovernanceEngine(registry=ModelRegistry())
        engine.log_action("m1", "deploy", "admin", {"ok": True})
        engine.log_action("m2", "retire", "admin")
        engine.log_action("m1", "promote", "admin")

        assert len(engine.get_audit_log()) == 3
        assert len(engine.get_audit_log(model_id="m1")) == 2
        assert len(engine.get_audit_log(limit=1)) == 1

    def test_compliance_missing_model(self):
        engine = AIGovernanceEngine(registry=ModelRegistry())
        result = engine.get_compliance_status("missing")
        assert result["error"] == "Model not found"

    def test_compliance_clean_model(self, registry):
        model_id = _register(registry)
        engine = AIGovernanceEngine(registry=registry)

        result = engine.get_compliance_status(model_id)

        assert result["compliance_score"] == 1.0
        assert result["requires_review"] is False
        assert result["drift_detected"] is False

    def test_compliance_penalties(self, registry):
        model_id = _register(registry)
        engine = AIGovernanceEngine(registry=registry)

        engine.drift_engine.drift_history[model_id] = [
            ModelDrift(drift_id="d1", model_id=model_id, drift_type=DriftType.DATA_DRIFT,
                       drift_score=0.9, severity="CRITICAL")
        ]
        engine.bias_engine.reports[model_id] = [
            BiasReport(report_id="r1", model_id=model_id, metric=BiasMetric.CALIBRATION,
                       score=0.4, threshold=0.8, is_fair=False)
        ]

        result = engine.get_compliance_status(model_id)

        assert result["compliance_score"] == 0.6
        assert result["drift_detected"] is True
        assert result["drift_severity"] == "CRITICAL"
        assert result["bias_issues"] == 1
        assert result["requires_review"] is True
