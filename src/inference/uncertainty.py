"""
Epistemic uncertainty for fraud risk scores via MC-Dropout.

A single forward pass gives a point estimate with no indication of how
much the model actually knows. Two transactions can both score 0.62 —
one because the model is consistently unsure, another because it is
torn between 0.2 and 0.95 depending on which units are dropped. The
first is a genuine borderline case; the second is a case the model has
no reliable opinion on, and routing it to a human is safer than either
BLOCK or ALLOW.

MC-Dropout (Gal & Ghahramani, "Dropout as a Bayesian Approximation",
ICML 2016) approximates that by keeping dropout active at inference and
sampling the predictive distribution: the spread across stochastic
passes is an estimate of epistemic uncertainty.

Note this is only meaningful for models that actually contain dropout
layers; `MCDropoutEstimator` reports how many it found so callers can
tell "confidently certain" apart from "no dropout to sample".
"""

import logging
import math
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from typing import Callable, Dict, List, Optional

import torch
import torch.nn as nn

logger = logging.getLogger(__name__)

# Uncertainty banding on the standard deviation of the predictive
# samples. A std of 0.15 on a [0, 1] risk score means passes routinely
# disagree by a third of the decision range, which is not a score any
# automated action should be taken on.
UNCERTAINTY_LOW = 0.05
UNCERTAINTY_HIGH = 0.15

CERTAINTY_CONFIDENT = "CONFIDENT"
CERTAINTY_MODERATE = "MODERATE"
CERTAINTY_UNCERTAIN = "UNCERTAIN"

# Dropout layers whose stochasticity we deliberately re-enable. Other
# train-mode-sensitive layers (BatchNorm in particular) must stay in
# eval mode or they would update running statistics during inference.
_DROPOUT_TYPES = (
    nn.Dropout,
    nn.Dropout1d,
    nn.Dropout2d,
    nn.Dropout3d,
    nn.AlphaDropout,
    nn.FeatureAlphaDropout,
)


@dataclass
class UncertaintyEstimate:
    """Predictive distribution summary for one scored transaction."""

    mean: float
    std: float
    lower_bound: float
    upper_bound: float
    predictive_entropy: float
    certainty: str
    is_uncertain: bool
    n_samples: int
    n_dropout_layers: int

    def to_dict(self) -> Dict:
        return asdict(self)


def _binary_entropy(p: float) -> float:
    """Shannon entropy of a Bernoulli(p), in nats. Peaks at p = 0.5."""
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -(p * math.log(p) + (1.0 - p) * math.log(1.0 - p))


def count_dropout_layers(model: nn.Module) -> int:
    """Number of dropout modules MC-Dropout can sample from."""
    return sum(1 for module in model.modules() if isinstance(module, _DROPOUT_TYPES))


@contextmanager
def dropout_enabled(model: nn.Module):
    """Temporarily put only the dropout layers into training mode.

    The model's overall eval mode is left untouched, so BatchNorm and
    friends keep using their running statistics and never update them.
    Original per-module modes are restored on exit, including when the
    body raises.
    """
    previous_modes = {}
    try:
        for name, module in model.named_modules():
            if isinstance(module, _DROPOUT_TYPES):
                previous_modes[name] = module.training
                module.train()
        yield model
    finally:
        for name, module in model.named_modules():
            if name in previous_modes:
                module.train(previous_modes[name])


class MCDropoutEstimator:
    """
    Estimates epistemic uncertainty by sampling a model with dropout on.

    Args:
        model: The scoring model. Must contain dropout layers for the
            estimate to carry information.
        n_samples: Number of stochastic forward passes.
        uncertain_threshold: Std above which a score is treated as too
            unreliable to act on automatically.
    """

    def __init__(
        self,
        model: nn.Module,
        n_samples: int = 30,
        uncertain_threshold: float = UNCERTAINTY_HIGH,
    ):
        if n_samples < 2:
            raise ValueError(
                f"n_samples must be at least 2 to measure spread, got {n_samples}"
            )
        self.model = model
        self.n_samples = n_samples
        self.uncertain_threshold = uncertain_threshold
        self.n_dropout_layers = count_dropout_layers(model)

        if self.n_dropout_layers == 0:
            logger.warning(
                "Model contains no dropout layers; MC-Dropout samples will be "
                "identical and the uncertainty estimate will always read zero."
            )

    def estimate(self, forward_fn: Callable[[], float]) -> UncertaintyEstimate:
        """
        Sample the predictive distribution of a scalar risk score.

        Args:
            forward_fn: Callable running one forward pass and returning
                the risk score as a float. Called n_samples times with
                dropout active.
        """
        with torch.no_grad(), dropout_enabled(self.model):
            samples = [float(forward_fn()) for _ in range(self.n_samples)]

        return self.summarize(samples)

    def summarize(self, samples: List[float]) -> UncertaintyEstimate:
        """Build an estimate from already-collected predictive samples."""
        if not samples:
            raise ValueError("No predictive samples to summarize")

        values = torch.tensor(samples, dtype=torch.float64)
        mean = float(values.mean())
        # Population std: these are the samples we drew, not a sample of
        # a larger set, and it keeps std well-defined for n_samples == 2.
        std = float(values.std(unbiased=False))

        if std >= self.uncertain_threshold:
            certainty = CERTAINTY_UNCERTAIN
        elif std >= UNCERTAINTY_LOW:
            certainty = CERTAINTY_MODERATE
        else:
            certainty = CERTAINTY_CONFIDENT

        return UncertaintyEstimate(
            mean=mean,
            std=std,
            # Two-std interval, clipped to the valid risk range
            lower_bound=max(0.0, mean - 2.0 * std),
            upper_bound=min(1.0, mean + 2.0 * std),
            predictive_entropy=_binary_entropy(mean),
            certainty=certainty,
            is_uncertain=bool(std >= self.uncertain_threshold),
            n_samples=len(samples),
            n_dropout_layers=self.n_dropout_layers,
        )


def apply_uncertainty_routing(
    decision: str,
    estimate: Optional[UncertaintyEstimate],
) -> str:
    """
    Downgrade an automated decision when the model is unsure.

    A BLOCK or ALLOW the model cannot reproduce across stochastic passes
    becomes a REVIEW, so a human adjudicates instead of the coin flip.
    REVIEW is already the cautious outcome and is left alone.
    """
    if estimate is None or not estimate.is_uncertain:
        return decision
    if decision in ("BLOCK", "ALLOW"):
        logger.info(
            "Routing %s to REVIEW: predictive std %.4f exceeds threshold",
            decision,
            estimate.std,
        )
        return "REVIEW"
    return decision
