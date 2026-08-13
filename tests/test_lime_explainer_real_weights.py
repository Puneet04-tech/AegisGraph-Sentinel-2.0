"""Tests that LIME explanations are derived from the model being explained.

The previous implementation never called a model: it perturbed each feature
randomly, averaged ``(perturbed - value)`` -- a quantity with expectation near
zero -- and multiplied by a further random factor.
"""

import inspect

import pytest

from src.explainable_ai import lime_explainer as lime_explainer_module
from src.explainable_ai.lime_explainer import LIMEExplainer
from src.explainable_ai.store import ExplainableAIStore


@pytest.fixture
def store():
    return ExplainableAIStore()


@pytest.fixture
def explainer(store):
    return LIMEExplainer(store=store)


def linear_model(coefficients):
    """A model whose local slopes are known exactly."""
    def predict(features):
        return sum(coefficients.get(k, 0.0) * v for k, v in features.items())
    return predict


def weights(explanation):
    return {f.feature: f.importance for f in explanation.features}


class TestDeterminism:
    """The same decision must explain the same way twice."""

    def test_module_does_not_import_random(self):
        source = inspect.getsource(lime_explainer_module)
        assert "import random" not in source

    def test_repeated_explanations_agree(self, explainer):
        features = {"amount": 2.0, "age": 4.0}
        predict = linear_model({"amount": 3.0, "age": -1.0})

        first = explainer.explain("d1", "m", "v1", features, 5.0, predict_fn=predict)
        second = explainer.explain("d1", "m", "v1", features, 5.0, predict_fn=predict)

        assert weights(first) == weights(second)

    def test_fallback_is_also_deterministic(self, explainer):
        features = {"amount": 2.0, "age": 4.0}

        first = explainer.explain("d1", "m", "v1", features, 0.8)
        second = explainer.explain("d1", "m", "v1", features, 0.8)

        assert weights(first) == weights(second)


class TestLocalApproximation:
    """Weights recover the model's local behaviour."""

    def test_linear_model_coefficients_are_recovered(self, explainer):
        features = {"amount": 2.0, "age": 4.0}
        predict = linear_model({"amount": 3.0, "age": -1.0})

        result = weights(explainer.explain(
            "d1", "m", "v1", features, 2.0, predict_fn=predict,
        ))

        # Weight is the slope scaled by the feature's own magnitude, so
        # features on different scales stay comparable.
        assert result["amount"] == pytest.approx(3.0 * 2.0)
        assert result["age"] == pytest.approx(-1.0 * 4.0)

    def test_ignored_features_get_zero_weight(self, explainer):
        features = {"amount": 2.0, "unused": 5.0}
        predict = linear_model({"amount": 3.0})

        result = weights(explainer.explain(
            "d1", "m", "v1", features, 6.0, predict_fn=predict,
        ))

        assert result["unused"] == pytest.approx(0.0)

    def test_flat_feature_is_reported_neutral(self, explainer):
        features = {"amount": 2.0, "unused": 5.0}
        predict = linear_model({"amount": 3.0})

        explanation = explainer.explain(
            "d1", "m", "v1", features, 6.0, predict_fn=predict,
        )
        directions = {f.feature: f.direction for f in explanation.features}

        assert directions["unused"] == "neutral"

    def test_sign_follows_the_model(self, explainer):
        features = {"risk": 1.0}

        rising = weights(explainer.explain(
            "d1", "m", "v1", features, 1.0,
            predict_fn=linear_model({"risk": 2.0}),
        ))
        falling = weights(explainer.explain(
            "d2", "m", "v1", features, 1.0,
            predict_fn=linear_model({"risk": -2.0}),
        ))

        assert rising["risk"] > 0
        assert falling["risk"] < 0

    def test_stronger_influence_ranks_higher(self, explainer):
        features = {"weak": 1.0, "strong": 1.0}
        predict = linear_model({"weak": 0.1, "strong": 5.0})

        explanation = explainer.explain(
            "d1", "m", "v1", features, 5.1, predict_fn=predict,
        )

        assert explanation.top_contributing_features[0] == "strong"

    def test_zero_valued_feature_is_still_probed(self, explainer):
        features = {"amount": 0.0}
        predict = linear_model({"amount": 4.0})

        result = weights(explainer.explain(
            "d1", "m", "v1", features, 0.0, predict_fn=predict,
        ))

        # A relative offset would move nothing from zero, so an absolute step
        # is used instead; the feature must not silently vanish.
        assert result["amount"] != 0.0

    def test_nonlinear_model_is_approximated_locally(self, explainer):
        # f(x) = x^2 has local slope 2x; at x = 3 that is 6, times step 3.
        def predict(features):
            return features["x"] ** 2

        result = weights(explainer.explain(
            "d1", "m", "v1", {"x": 3.0}, 9.0, predict_fn=predict,
        ))

        assert result["x"] == pytest.approx(6.0 * 3.0, rel=0.15)

    def test_failing_model_does_not_break_the_explanation(self, explainer):
        def predict(features):
            raise RuntimeError("model unavailable")

        explanation = explainer.explain(
            "d1", "m", "v1", {"amount": 1.0}, 0.5, predict_fn=predict,
        )

        assert weights(explanation)["amount"] == 0.0


class TestMetadata:
    """An explanation says how it was produced."""

    def test_model_based_explanations_are_labelled_lime(self, explainer):
        explanation = explainer.explain(
            "d1", "m", "v1", {"amount": 1.0}, 1.0,
            predict_fn=linear_model({"amount": 1.0}),
        )

        assert explanation.metadata["method"] == "LIME"
        assert explanation.metadata["model_based"] is True
        assert explanation.metadata["num_samples"] > 0

    def test_fallback_does_not_claim_to_be_lime(self, explainer):
        explanation = explainer.explain("d1", "m", "v1", {"amount": 1.0}, 1.0)

        assert explanation.metadata["method"] == "value_attribution"
        assert explanation.metadata["model_based"] is False

    def test_fallback_attributes_by_magnitude(self, explainer):
        explanation = explainer.explain(
            "d1", "m", "v1", {"big": 3.0, "small": 1.0}, 1.0,
        )

        result = weights(explanation)
        assert result["big"] == pytest.approx(0.75)
        assert result["small"] == pytest.approx(0.25)

    def test_all_zero_features_do_not_divide_by_zero(self, explainer):
        explanation = explainer.explain("d1", "m", "v1", {"a": 0.0, "b": 0.0}, 1.0)

        assert set(weights(explanation).values()) == {0.0}
