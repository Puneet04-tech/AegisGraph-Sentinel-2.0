"""Unit tests for model-probing counterfactual explanations.

The predict function is a known linear scorer, so every expected
counterfactual can be computed by hand:

    risk = clip(0.5 * amount + 0.3 * degree + 0.1 * velocity, 0, 1)

with features in [0, 1] and a 0.5 decision threshold.
"""

import pytest

from src.explainable_ai.counterfactual_generator import CounterfactualGenerator
from src.explainable_ai.shap_explainer import SHAPExplainer
from src.explainable_ai.store import ExplainableAIStore


def linear_risk(features):
    score = (
        0.5 * features["amount"]
        + 0.3 * features["degree"]
        + 0.1 * features["velocity"]
    )
    return min(1.0, max(0.0, score))


# risk = 0.45 + 0.15 + 0.05 = 0.65 -> fraud side of the 0.5 threshold
FRAUD_FEATURES = {"amount": 0.9, "degree": 0.5, "velocity": 0.5}

# Features live in [0, 1]
UNIT_BOUNDS = {
    "amount": (0.0, 1.0),
    "degree": (0.0, 1.0),
    "velocity": (0.0, 1.0),
}


@pytest.fixture
def store():
    return ExplainableAIStore()


def _generator(store, **overrides):
    kwargs = dict(
        predict_fn=linear_risk,
        threshold=0.5,
        feature_bounds=UNIT_BOUNDS,
        store=store,
    )
    kwargs.update(overrides)
    return CounterfactualGenerator(**kwargs)


class TestDecisionFlips:
    def test_fraud_to_non_fraud_flip_is_verified(self, store):
        cf = _generator(store).generate("dec-1", FRAUD_FEATURES)

        assert cf is not None
        assert cf.outcome_change == "fraud to non-fraud"
        assert linear_risk(cf.counterfactual_instance) < 0.5

    def test_single_feature_change_preferred(self, store):
        # Dropping amount alone can cross the boundary, so the sparse
        # single-feature counterfactual must be chosen
        cf = _generator(store).generate("dec-2", FRAUD_FEATURES)

        assert cf.changed_features == ["amount"]

    def test_minimal_change_found_by_bisection(self, store):
        # Boundary: 0.5*a + 0.2 = 0.49 (threshold - margin) -> a = 0.58
        cf = _generator(store).generate("dec-3", FRAUD_FEATURES)
        new_amount = cf.counterfactual_instance["amount"]

        assert new_amount == pytest.approx(0.58, abs=0.01)
        # Original instance must be untouched
        assert cf.original_instance["amount"] == pytest.approx(0.9)

    def test_non_fraud_to_fraud_direction(self, store):
        # risk = 0.1 + 0.03 + 0.01 = 0.14 -> needs to rise above 0.51
        features = {"amount": 0.2, "degree": 0.1, "velocity": 0.1}
        cf = _generator(store).generate("dec-4", features)

        assert cf is not None
        assert cf.outcome_change == "non-fraud to fraud"
        assert linear_risk(cf.counterfactual_instance) > 0.5


class TestConstraints:
    def test_immutable_features_never_changed(self, store):
        # With amount frozen, flipping needs degree AND velocity at 0:
        # 0.45 + 0 + 0 = 0.45 < 0.49
        cf = _generator(
            store, immutable_features=["amount"]
        ).generate("dec-5", FRAUD_FEATURES)

        assert cf is not None
        assert "amount" not in cf.changed_features
        assert set(cf.changed_features) == {"degree", "velocity"}

    def test_feature_bounds_respected(self, store):
        # Amount cannot go below 0.8: 0.5*0.8 + 0.2 = 0.6, so a
        # single-amount flip is impossible and other features must move
        bounds = dict(UNIT_BOUNDS, amount=(0.8, 1.0))
        cf = _generator(store, feature_bounds=bounds).generate(
            "dec-6", FRAUD_FEATURES
        )

        assert cf is not None
        assert cf.counterfactual_instance["amount"] >= 0.8
        assert linear_risk(cf.counterfactual_instance) < 0.5

    def test_returns_none_when_no_flip_reachable(self, store):
        # Constant model: nothing can ever flip
        generator = CounterfactualGenerator(
            predict_fn=lambda features: 0.9,
            feature_bounds=UNIT_BOUNDS,
            store=store,
        )

        assert generator.generate("dec-7", FRAUD_FEATURES) is None

    def test_sparsity_budget_limits_changes(self, store):
        # Only one change allowed but amount is frozen, so the flip
        # (which needs two features) must be given up
        cf = _generator(
            store,
            immutable_features=["amount"],
            max_features_changed=1,
        ).generate("dec-8", FRAUD_FEATURES)

        assert cf is None

    def test_input_features_not_mutated(self, store):
        features = dict(FRAUD_FEATURES)
        _generator(store).generate("dec-9", features)

        assert features == FRAUD_FEATURES


class TestScores:
    def test_proximity_and_sparsity_ranges(self, store):
        cf = _generator(store).generate("dec-10", FRAUD_FEATURES)

        assert 0.0 <= cf.proximity_score <= 1.0
        assert 0.0 <= cf.sparsity_score <= 1.0

    def test_sparsity_reflects_unchanged_fraction(self, store):
        # One of three features changed -> sparsity 1 - 1/3
        cf = _generator(store).generate("dec-11", FRAUD_FEATURES)

        assert cf.sparsity_score == pytest.approx(2 / 3, abs=1e-3)

    def test_counterfactual_persisted_to_store(self, store):
        cf = _generator(store).generate("dec-12", FRAUD_FEATURES)
        stored = store.get_decision_counterfactuals("dec-12")

        assert [c.cf_id for c in stored] == [cf.cf_id]


class TestSHAPExplainerIntegration:
    def test_explain_uses_real_generator_when_predict_fn_given(self, store):
        explainer = SHAPExplainer(store=store, predict_fn=linear_risk)
        explainer.explain(
            decision_id="dec-13",
            model_id="htgnn",
            model_version="2.1",
            input_features=dict(FRAUD_FEATURES),
            prediction_value=linear_risk(FRAUD_FEATURES),
        )

        stored = store.get_decision_counterfactuals("dec-13")
        assert len(stored) == 1
        # A real, verified flip — not an invented perturbation
        assert linear_risk(stored[0].counterfactual_instance) < 0.5

    def test_fallback_without_predict_fn_is_deterministic(self, store):
        explainer = SHAPExplainer(store=store)

        first = explainer._generate_counterfactual(
            "dec-14", dict(FRAUD_FEATURES), 0.65
        )
        second = explainer._generate_counterfactual(
            "dec-15", dict(FRAUD_FEATURES), 0.65
        )

        assert first.counterfactual_instance == second.counterfactual_instance
        assert first.feature_changes == second.feature_changes
        # Halves the largest-magnitude features
        assert first.counterfactual_instance["amount"] == pytest.approx(0.45)
