"""
Post-hoc calibration for HTGNN risk outputs.

The decision thresholds treat risk scores as probabilities ("22% risk",
"56% -> REVIEW"), but a model trained with focal loss has no guarantee
that a 0.56 output means a 56% fraud rate. This module provides:

- TemperatureScaler: single-parameter temperature scaling
  (Guo et al., "On Calibration of Modern Neural Networks", ICML 2017)
- expected_calibration_error: positive-class ECE over equal-width bins
- reliability_curve: per-bin statistics for reliability diagrams

Temperature scaling divides the log-odds by a learned scalar T before
the sigmoid. It never changes the ranking of scores (ROC-AUC and
PR-AUC are preserved); it only fixes over/under-confidence.
"""

import logging
from typing import Dict, List, Union

import numpy as np
import torch
import torch.nn as nn

logger = logging.getLogger(__name__)

ArrayLike = Union[np.ndarray, torch.Tensor, List[float]]

# Clamp probabilities away from {0, 1} before taking log-odds
_EPS = 1e-7


def _to_tensor(values: ArrayLike) -> torch.Tensor:
    """Convert array-like probabilities/labels to a float tensor."""
    if isinstance(values, torch.Tensor):
        return values.detach().float().flatten()
    return torch.as_tensor(np.asarray(values), dtype=torch.float32).flatten()


def probs_to_logits(probs: ArrayLike) -> torch.Tensor:
    """Convert probabilities to log-odds, clamped away from 0 and 1."""
    p = _to_tensor(probs).clamp(_EPS, 1.0 - _EPS)
    return torch.log(p / (1.0 - p))


class TemperatureScaler(nn.Module):
    """
    Learns a single temperature T > 0 on held-out validation data by
    minimizing the negative log-likelihood of sigmoid(logits / T).

    The model outputs probabilities, so inputs are converted to
    log-odds internally; callers only ever deal in probabilities.
    """

    def __init__(self):
        super().__init__()
        # Parameterized as log(T) so T stays positive during optimization
        self.log_temperature = nn.Parameter(torch.zeros(1))

    @property
    def temperature(self) -> float:
        return float(self.log_temperature.exp())

    def fit(
        self,
        probs: ArrayLike,
        labels: ArrayLike,
        lr: float = 0.05,
        max_iter: int = 200,
    ) -> float:
        """
        Fit the temperature on validation predictions.

        Args:
            probs: Predicted fraud probabilities on the validation set
            labels: Ground-truth labels (0/1)
            lr: LBFGS learning rate
            max_iter: Maximum LBFGS iterations

        Returns:
            The learned temperature
        """
        logits = probs_to_logits(probs)
        targets = _to_tensor(labels)

        optimizer = torch.optim.LBFGS(
            [self.log_temperature], lr=lr, max_iter=max_iter
        )
        nll = nn.BCEWithLogitsLoss()

        def closure():
            optimizer.zero_grad()
            loss = nll(logits / self.log_temperature.exp(), targets)
            loss.backward()
            return loss

        optimizer.step(closure)
        logger.info("Fitted temperature: %.4f", self.temperature)
        return self.temperature

    def transform(self, probs: ArrayLike) -> np.ndarray:
        """Return calibrated probabilities (ranking is preserved)."""
        with torch.no_grad():
            logits = probs_to_logits(probs)
            calibrated = torch.sigmoid(logits / self.log_temperature.exp())
        return calibrated.numpy()

    def load_temperature(self, temperature: float) -> None:
        """Restore a previously fitted temperature (e.g. from a checkpoint)."""
        if temperature <= 0:
            raise ValueError(f"temperature must be positive, got {temperature}")
        with torch.no_grad():
            self.log_temperature.fill_(float(np.log(temperature)))


def expected_calibration_error(
    probs: ArrayLike,
    labels: ArrayLike,
    n_bins: int = 10,
) -> float:
    """
    Positive-class Expected Calibration Error.

    Bins predictions into equal-width probability bins and returns the
    weighted mean |mean predicted probability - observed fraud rate|.
    0.0 means "a 56% score really is fraud 56% of the time".
    """
    p = _to_tensor(probs).numpy()
    y = _to_tensor(labels).numpy()

    if p.size == 0:
        return 0.0

    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    # Right-inclusive last bin so p == 1.0 is counted
    bin_ids = np.clip(np.digitize(p, bin_edges[1:-1]), 0, n_bins - 1)

    ece = 0.0
    for b in range(n_bins):
        mask = bin_ids == b
        if not mask.any():
            continue
        ece += (mask.mean()) * abs(p[mask].mean() - y[mask].mean())
    return float(ece)


def reliability_curve(
    probs: ArrayLike,
    labels: ArrayLike,
    n_bins: int = 10,
) -> List[Dict[str, float]]:
    """
    Per-bin data for a reliability diagram.

    Returns one entry per non-empty bin:
    {bin_lower, bin_upper, mean_predicted, observed_frequency, count}
    A perfectly calibrated model has mean_predicted equal to
    observed_frequency in every bin.
    """
    p = _to_tensor(probs).numpy()
    y = _to_tensor(labels).numpy()

    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    bin_ids = np.clip(np.digitize(p, bin_edges[1:-1]), 0, n_bins - 1)

    curve = []
    for b in range(n_bins):
        mask = bin_ids == b
        if not mask.any():
            continue
        curve.append({
            "bin_lower": float(bin_edges[b]),
            "bin_upper": float(bin_edges[b + 1]),
            "mean_predicted": float(p[mask].mean()),
            "observed_frequency": float(y[mask].mean()),
            "count": int(mask.sum()),
        })
    return curve
