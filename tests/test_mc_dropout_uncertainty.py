"""Tests for MC-Dropout epistemic uncertainty and REVIEW routing.

Predictive samples are supplied directly where possible, so expected
means, standard deviations, and entropies are computed from the
definitions rather than from a previous run of the code.
"""
from __future__ import annotations

import math
import os

import pytest

if os.getenv("RUN_TORCH_TESTS", "").lower() != "true":
    pytest.skip("PyTorch tests require RUN_TORCH_TESTS=true", allow_module_level=True)

# Handle optional torch dependency
try:
    import torch
    import torch.nn as nn
    from src.inference.uncertainty import (
        CERTAINTY_CONFIDENT,
        CERTAINTY_MODERATE,
        CERTAINTY_UNCERTAIN,
        MCDropoutEstimator,
        UncertaintyEstimate,
        apply_uncertainty_routing,
        count_dropout_layers,
        dropout_enabled,
    )
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

pytestmark = pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch not installed")


if TORCH_AVAILABLE:

    class DropoutModel(nn.Module):
        """Model whose output is genuinely stochastic under dropout."""

        def __init__(self, p: float = 0.5):
            super().__init__()
            self.dropout = nn.Dropout(p=p)
            self.norm = nn.BatchNorm1d(4)

        def forward(self, x):
            return self.dropout(x).mean()

    class DeterministicModel(nn.Module):
        """No dropout: MC-Dropout has nothing to sample."""

        def __init__(self):
            super().__init__()
            self.linear = nn.Linear(4, 1)

        def forward(self, x):
            return self.linear(x).mean()


def _estimator(model=None, **kwargs):
    return MCDropoutEstimator(model or DropoutModel(), **kwargs)


class TestDropoutDiscovery:
    def test_counts_dropout_layers_only(self):
        assert count_dropout_layers(DropoutModel()) == 1
        assert count_dropout_layers(DeterministicModel()) == 0

    def test_counts_nested_dropout_variants(self):
        model = nn.Sequential(
            nn.Dropout(0.2),
            nn.Sequential(nn.AlphaDropout(0.1), nn.Dropout2d(0.3)),
            nn.Linear(2, 2),
        )

        assert count_dropout_layers(model) == 3

    def test_warns_when_model_has_no_dropout(self, caplog):
        with caplog.at_level("WARNING"):
            MCDropoutEstimator(DeterministicModel())

        assert "no dropout layers" in caplog.text


class TestDropoutEnabledContext:
    def test_enables_dropout_without_leaving_eval_mode(self):
        model = DropoutModel()
        model.eval()

        with dropout_enabled(model):
            assert model.dropout.training is True
            # BatchNorm must stay in eval mode or it would update its
            # running statistics during inference
            assert model.norm.training is False

        assert model.dropout.training is False

    def test_restores_original_modes_on_exception(self):
        model = DropoutModel()
        model.eval()

        with pytest.raises(RuntimeError):
            with dropout_enabled(model):
                raise RuntimeError("boom")

        assert model.dropout.training is False

    def test_restores_training_mode_when_model_was_training(self):
        model = DropoutModel()
        model.train()

        with dropout_enabled(model):
            assert model.dropout.training is True

        assert model.dropout.training is True


class TestSummarize:
    def test_mean_and_population_std_match_definition(self):
        samples = [0.2, 0.4, 0.6, 0.8]
        estimate = _estimator().summarize(samples)

        expected_mean = 0.5
        expected_std = math.sqrt(sum((s - expected_mean) ** 2 for s in samples) / 4)

        assert estimate.mean == pytest.approx(expected_mean)
        assert estimate.std == pytest.approx(expected_std)
        assert estimate.n_samples == 4

    def test_identical_samples_have_zero_spread(self):
        estimate = _estimator().summarize([0.7] * 10)

        assert estimate.std == pytest.approx(0.0)
        assert estimate.certainty == CERTAINTY_CONFIDENT
        assert estimate.is_uncertain is False

    def test_predictive_entropy_is_maximal_at_one_half(self):
        balanced = _estimator().summarize([0.5, 0.5])
        skewed = _estimator().summarize([0.99, 0.99])

        assert balanced.predictive_entropy == pytest.approx(math.log(2))
        assert skewed.predictive_entropy < balanced.predictive_entropy

    @pytest.mark.parametrize("mean", [0.0, 1.0])
    def test_entropy_is_zero_at_the_boundaries(self, mean):
        assert _estimator().summarize([mean, mean]).predictive_entropy == 0.0

    def test_bounds_are_two_std_and_clipped_to_valid_range(self):
        estimate = _estimator().summarize([0.4, 0.6])

        assert estimate.lower_bound == pytest.approx(0.5 - 2 * 0.1)
        assert estimate.upper_bound == pytest.approx(0.5 + 2 * 0.1)

        extreme = _estimator().summarize([0.0, 1.0])
        assert extreme.lower_bound == 0.0
        assert extreme.upper_bound == 1.0

    @pytest.mark.parametrize(
        ("samples", "expected"),
        [
            ([0.50, 0.50, 0.51], CERTAINTY_CONFIDENT),   # std ~0.005
            ([0.40, 0.50, 0.60], CERTAINTY_MODERATE),    # std ~0.082
            ([0.10, 0.50, 0.90], CERTAINTY_UNCERTAIN),   # std ~0.327
        ],
    )
    def test_certainty_banding(self, samples, expected):
        assert _estimator().summarize(samples).certainty == expected

    def test_is_uncertain_is_a_python_bool(self):
        estimate = _estimator().summarize([0.1, 0.9])

        # A numpy/torch bool here would break JSON serialization
        assert estimate.is_uncertain is True

    def test_empty_samples_rejected(self):
        with pytest.raises(ValueError):
            _estimator().summarize([])

    def test_to_dict_exposes_full_estimate(self):
        estimate = _estimator().summarize([0.3, 0.5])

        assert set(estimate.to_dict()) == {
            "mean", "std", "lower_bound", "upper_bound", "predictive_entropy",
            "certainty", "is_uncertain", "n_samples", "n_dropout_layers",
        }


class TestEstimate:
    def test_samples_vary_for_a_model_with_dropout(self):
        torch.manual_seed(0)
        model = DropoutModel(p=0.5)
        model.eval()
        x = torch.ones(8)

        estimate = _estimator(model, n_samples=25).estimate(lambda: model(x))

        assert estimate.n_samples == 25
        assert estimate.n_dropout_layers == 1
        assert estimate.std > 0.0

    def test_model_without_dropout_yields_zero_uncertainty(self):
        model = DeterministicModel()
        model.eval()
        x = torch.ones(4)

        estimate = _estimator(model, n_samples=10).estimate(lambda: model(x))

        assert estimate.std == pytest.approx(0.0)
        assert estimate.n_dropout_layers == 0
        assert estimate.is_uncertain is False

    def test_model_left_in_eval_mode_after_estimating(self):
        model = DropoutModel()
        model.eval()
        x = torch.ones(8)

        _estimator(model, n_samples=5).estimate(lambda: model(x))

        assert model.dropout.training is False
        assert model.training is False

    def test_forward_fn_called_once_per_sample(self):
        calls = []

        def forward():
            calls.append(1)
            return 0.5

        _estimator(n_samples=7).estimate(forward)

        assert len(calls) == 7

    @pytest.mark.parametrize("bad_n", [0, 1, -3])
    def test_requires_at_least_two_samples(self, bad_n):
        with pytest.raises(ValueError, match="n_samples"):
            _estimator(n_samples=bad_n)


class TestUncertaintyRouting:
    @pytest.mark.parametrize("decision", ["BLOCK", "ALLOW"])
    def test_uncertain_automated_decisions_become_review(self, decision):
        uncertain = _estimator().summarize([0.1, 0.9])

        assert apply_uncertainty_routing(decision, uncertain) == "REVIEW"

    @pytest.mark.parametrize("decision", ["BLOCK", "ALLOW", "REVIEW"])
    def test_confident_decisions_are_untouched(self, decision):
        confident = _estimator().summarize([0.8, 0.8])

        assert apply_uncertainty_routing(decision, confident) == decision

    def test_review_stays_review_when_uncertain(self):
        uncertain = _estimator().summarize([0.1, 0.9])

        assert apply_uncertainty_routing("REVIEW", uncertain) == "REVIEW"

    def test_missing_estimate_leaves_decision_unchanged(self):
        assert apply_uncertainty_routing("BLOCK", None) == "BLOCK"

    def test_threshold_is_configurable(self):
        samples = [0.45, 0.55]  # std = 0.05

        strict = MCDropoutEstimator(
            DropoutModel(), uncertain_threshold=0.01
        ).summarize(samples)
        lenient = MCDropoutEstimator(
            DropoutModel(), uncertain_threshold=0.9
        ).summarize(samples)

        assert apply_uncertainty_routing("BLOCK", strict) == "REVIEW"
        assert apply_uncertainty_routing("BLOCK", lenient) == "BLOCK"
