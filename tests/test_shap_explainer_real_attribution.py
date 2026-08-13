"""Tests that SHAP attributions are derived, not drawn.

Contributions were split by ``random.uniform(0.8, 1.2)``, per-feature
confidence was ``random.uniform(0.85, 0.99)``, and a model with no stored
explanations reported five invented features named feature_0..feature_4.
"""

import inspect

import pytest

from src.explainable_ai import shap_explainer as shap_explainer_module
from src.explainable_ai.shap_explainer import SHAPExplainer
from src.explainable_ai.store import ExplainableAIStore


@pytest.fixture
def store():
    return ExplainableAIStore()


def linear_model(coefficients):
    def predict(features):
        return sum(coefficients.get(k, 0.0) * v for k, v in features.items())
    return predict


def weights(explanation):
    return {f.feature: f.importance for f in explanation.features}


class TestDeterminism:
    """Attributions must be reproducible."""

    def test_module_does_not_import_random(self):
        source = inspect.getsource(shap_explainer_module)
        assert "import random" not in source

    def test_repeated_explanations_agree(self, store):
        explainer = SHAPExplainer(store=store)
        features = {"amount": 2.0, "age": 4.0}

        first = explainer.explain("d1", "m", "v1", features, 0.0, 0.9)
        second = explainer.explain("d1", "m", "v1", features, 0.0, 0.9)

        assert weights(first) == weights(second)

    def test_confidence_is_reproducible(self, store):
        explainer = SHAPExplainer(store=store)
        features = {"amount": 2.0, "age": 4.0}

        first = explainer.explain("d1", "m", "v1", features, 0.0, 0.9)
        second = explainer.explain("d1", "m", "v1", features, 0.0, 0.9)

        assert first.confidence == second.confidence


class TestAdditivity:
    """Contributions sum to prediction minus base value."""

    @pytest.mark.parametrize("base,prediction", [
        (0.0, 0.9), (0.3, 0.8), (0.5, 0.1), (0.0, 0.0), (0.2, 0.2),
    ])
    def test_contributions_sum_to_the_gap(self, store, base, prediction):
        explainer = SHAPExplainer(store=store)
        features = {"a": 1.0, "b": 2.0, "c": 3.0}

        explanation = explainer.explain("d1", "m", "v1", features, base, prediction)

        assert sum(weights(explanation).values()) == pytest.approx(prediction - base)

    def test_additivity_holds_with_a_model(self, store):
        explainer = SHAPExplainer(store=store, predict_fn=linear_model({"a": 3.0, "b": -1.0}))
        features = {"a": 2.0, "b": 4.0}

        explanation = explainer.explain("d1", "m", "v1", features, 0.0, 2.0)

        assert sum(weights(explanation).values()) == pytest.approx(2.0)

    def test_all_zero_features_split_evenly(self, store):
        explainer = SHAPExplainer(store=store)

        explanation = explainer.explain("d1", "m", "v1", {"a": 0.0, "b": 0.0}, 0.0, 1.0)

        assert weights(explanation) == {"a": pytest.approx(0.5), "b": pytest.approx(0.5)}

    def test_no_features_yields_no_attribution(self, store):
        explainer = SHAPExplainer(store=store)

        assert explainer.explain("d1", "m", "v1", {}, 0.0, 1.0).features == []


class TestModelBasedAttribution:
    """With a model, contributions are measured by ablation."""

    def test_linear_contributions_are_recovered(self, store):
        explainer = SHAPExplainer(
            store=store, predict_fn=linear_model({"amount": 3.0, "age": -1.0}),
        )
        features = {"amount": 2.0, "age": 4.0}

        result = weights(explainer.explain("d1", "m", "v1", features, 0.0, 2.0))

        assert result["amount"] == pytest.approx(6.0)
        assert result["age"] == pytest.approx(-4.0)

    def test_ignored_feature_contributes_nothing(self, store):
        explainer = SHAPExplainer(store=store, predict_fn=linear_model({"amount": 3.0}))
        features = {"amount": 2.0, "unused": 5.0}

        result = weights(explainer.explain("d1", "m", "v1", features, 0.0, 6.0))

        assert result["unused"] == pytest.approx(0.0)

    def test_flat_feature_reads_neutral(self, store):
        explainer = SHAPExplainer(store=store, predict_fn=linear_model({"amount": 3.0}))
        features = {"amount": 2.0, "unused": 5.0}

        explanation = explainer.explain("d1", "m", "v1", features, 0.0, 6.0)
        directions = {f.feature: f.direction for f in explanation.features}

        assert directions["unused"] == "neutral"

    def test_failing_model_degrades_without_raising(self, store):
        def predict(features):
            raise RuntimeError("unavailable")

        explainer = SHAPExplainer(store=store, predict_fn=predict)

        explanation = explainer.explain("d1", "m", "v1", {"a": 1.0, "b": 2.0}, 0.0, 1.0)

        assert sum(weights(explanation).values()) == pytest.approx(1.0)


class TestConfidence:
    """Per-feature confidence reflects attribution concentration."""

    def test_dominant_feature_carries_more_confidence(self, store):
        explainer = SHAPExplainer(store=store)

        explanation = explainer.explain(
            "d1", "m", "v1", {"big": 9.0, "small": 1.0}, 0.0, 1.0,
        )
        confidences = {f.feature: f.confidence for f in explanation.features}

        assert confidences["big"] > confidences["small"]

    def test_confidences_sum_to_one(self, store):
        explainer = SHAPExplainer(store=store)

        explanation = explainer.explain(
            "d1", "m", "v1", {"a": 1.0, "b": 2.0, "c": 3.0}, 0.0, 1.0,
        )

        total = sum(f.confidence for f in explanation.features)
        assert total == pytest.approx(1.0)


class TestGlobalImportance:
    """Global importance never invents feature names."""

    def test_unknown_model_returns_nothing(self, store):
        explainer = SHAPExplainer(store=store)

        assert explainer.get_global_importance("never_seen") == []

    def test_no_invented_feature_names(self, store):
        explainer = SHAPExplainer(store=store)

        names = [f.feature for f in explainer.get_global_importance("never_seen")]

        assert not any(name.startswith("feature_") for name in names)

    def test_importance_aggregates_stored_explanations(self, store):
        explainer = SHAPExplainer(store=store)
        explainer.explain("d1", "m1", "v1", {"amount": 5.0, "age": 1.0}, 0.0, 1.0)
        explainer.explain("d2", "m1", "v1", {"amount": 5.0, "age": 1.0}, 0.0, 1.0)

        names = [f.feature for f in explainer.get_global_importance("m1")]

        assert set(names) == {"amount", "age"}
