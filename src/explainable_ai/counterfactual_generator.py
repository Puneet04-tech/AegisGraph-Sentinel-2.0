"""
Model-probing counterfactual explanation generator.

Answers the question a blocked customer (or an RBI auditor) actually
asks: "what minimal change would have flipped this decision?" —
by probing the real scoring function, not by fabricating deltas.

Search strategy:
- greedy feature selection: try to flip the decision by changing one
  feature; if no single feature suffices, lock in the most effective
  move and repeat with the remaining features
- per-feature bisection: once a flipping direction is found, binary
  search the minimal change magnitude that still flips the decision
- every returned counterfactual is verified against the model before
  being stored; if no flip is reachable within the configured bounds,
  None is returned instead of an invented answer
"""

import logging
from typing import Callable, Dict, List, Optional, Tuple

from .models import CounterfactualExplanation
from .store import ExplainableAIStore, get_xai_store

logger = logging.getLogger(__name__)

PredictFn = Callable[[Dict[str, float]], float]


class CounterfactualGenerator:
    """
    Finds sparse, minimal counterfactuals for a binary risk decision.

    Args:
        predict_fn: Callable mapping a feature dict to a risk
            probability in [0, 1] (the real model / scorer).
        threshold: Decision boundary; scores >= threshold are fraud.
        feature_bounds: Optional {feature: (low, high)} search bounds.
            Features without bounds get a symmetric default range
            around their original value.
        immutable_features: Features the search must never change
            (e.g. account age, regulatory fields).
        max_features_changed: Sparsity budget — the search gives up
            rather than change more features than this.
        bisection_steps: Iterations of binary search per feature.
        margin: How far past the threshold the counterfactual must
            land, so it does not sit exactly on the boundary.
    """

    def __init__(
        self,
        predict_fn: PredictFn,
        threshold: float = 0.5,
        feature_bounds: Optional[Dict[str, Tuple[float, float]]] = None,
        immutable_features: Optional[List[str]] = None,
        max_features_changed: int = 3,
        bisection_steps: int = 25,
        margin: float = 0.01,
        store: Optional[ExplainableAIStore] = None,
    ):
        self._predict_fn = predict_fn
        self._threshold = threshold
        self._feature_bounds = feature_bounds or {}
        self._immutable = set(immutable_features or [])
        self._max_features_changed = max_features_changed
        self._bisection_steps = bisection_steps
        self._margin = margin
        self._store = store or get_xai_store()

    def generate(
        self,
        decision_id: str,
        features: Dict[str, float],
    ) -> Optional[CounterfactualExplanation]:
        """
        Search for a minimal feature change that flips the decision.

        Returns a verified CounterfactualExplanation (also persisted to
        the store), or None when no flip is reachable within bounds and
        the sparsity budget.
        """
        original = dict(features)
        p_original = self._predict_fn(original)
        was_fraud = p_original >= self._threshold

        candidate = dict(original)
        changed: List[str] = []

        for _ in range(self._max_features_changed):
            flip = self._best_single_feature_flip(candidate, changed, was_fraud)
            if flip is not None:
                name, value = flip
                candidate[name] = value
                changed.append(name)
                return self._build_explanation(
                    decision_id, original, candidate, changed, was_fraud
                )

            # No single remaining feature flips the decision: lock in the
            # move that gets closest to the boundary and keep searching.
            step = self._most_effective_move(candidate, changed, was_fraud)
            if step is None:
                break
            name, value = step
            candidate[name] = value
            changed.append(name)

        logger.info(
            "No counterfactual found for decision %s within %d feature changes",
            decision_id,
            self._max_features_changed,
        )
        return None

    # ------------------------------------------------------------------
    # Search internals
    # ------------------------------------------------------------------

    def _flips(self, probability: float, was_fraud: bool) -> bool:
        """Whether a probability lands on the other side of the boundary."""
        if was_fraud:
            return probability <= self._threshold - self._margin
        return probability >= self._threshold + self._margin

    def _bounds_for(self, name: str, original_value: float) -> Tuple[float, float]:
        if name in self._feature_bounds:
            return self._feature_bounds[name]
        half_range = 2.0 * abs(original_value) + 1.0
        return (original_value - half_range, original_value + half_range)

    def _mutable_features(
        self, features: Dict[str, float], changed: List[str]
    ) -> List[str]:
        return [
            name
            for name, value in features.items()
            if name not in self._immutable
            and name not in changed
            and isinstance(value, (int, float))
            and not isinstance(value, bool)
        ]

    def _best_single_feature_flip(
        self,
        features: Dict[str, float],
        changed: List[str],
        was_fraud: bool,
    ) -> Optional[Tuple[str, float]]:
        """
        Try flipping with one more feature; among features that can flip
        the decision, return the one with the smallest normalized change.
        """
        best: Optional[Tuple[str, float]] = None
        best_cost = float("inf")

        for name in self._mutable_features(features, changed):
            original_value = features[name]
            low, high = self._bounds_for(name, original_value)

            for endpoint in (low, high):
                if endpoint == original_value:
                    continue
                probe = dict(features)
                probe[name] = endpoint
                if not self._flips(self._predict_fn(probe), was_fraud):
                    continue

                value = self._minimal_flip_value(
                    features, name, original_value, endpoint, was_fraud
                )
                span = abs(high - low) or 1.0
                cost = abs(value - original_value) / span
                if cost < best_cost:
                    best_cost = cost
                    best = (name, value)

        return best

    def _minimal_flip_value(
        self,
        features: Dict[str, float],
        name: str,
        original_value: float,
        flipping_value: float,
        was_fraud: bool,
    ) -> float:
        """
        Bisect between the original value (no flip) and a known flipping
        value to find the smallest change that still flips the decision.
        """
        no_flip = original_value
        flip = flipping_value

        for _ in range(self._bisection_steps):
            midpoint = (no_flip + flip) / 2.0
            probe = dict(features)
            probe[name] = midpoint
            if self._flips(self._predict_fn(probe), was_fraud):
                flip = midpoint
            else:
                no_flip = midpoint

        return flip

    def _most_effective_move(
        self,
        features: Dict[str, float],
        changed: List[str],
        was_fraud: bool,
    ) -> Optional[Tuple[str, float]]:
        """
        Greedy fallback: the bound endpoint that moves the score furthest
        toward the decision boundary, used when no single feature flips.
        """
        p_current = self._predict_fn(features)
        best: Optional[Tuple[str, float]] = None
        best_probability = p_current

        for name in self._mutable_features(features, changed):
            low, high = self._bounds_for(name, features[name])
            for endpoint in (low, high):
                probe = dict(features)
                probe[name] = endpoint
                p = self._predict_fn(probe)
                improves = p < best_probability if was_fraud else p > best_probability
                if improves:
                    best_probability = p
                    best = (name, endpoint)

        return best

    # ------------------------------------------------------------------
    # Result construction
    # ------------------------------------------------------------------

    def _build_explanation(
        self,
        decision_id: str,
        original: Dict[str, float],
        counterfactual: Dict[str, float],
        changed: List[str],
        was_fraud: bool,
    ) -> CounterfactualExplanation:
        # Verify against the model before reporting anything
        p_counterfactual = self._predict_fn(counterfactual)
        if not self._flips(p_counterfactual, was_fraud):
            logger.warning(
                "Counterfactual for %s failed verification; discarding",
                decision_id,
            )
            return None

        normalized_changes = []
        for name in changed:
            low, high = self._bounds_for(name, original[name])
            span = abs(high - low) or 1.0
            normalized_changes.append(
                abs(counterfactual[name] - original[name]) / span
            )
        proximity = max(0.0, 1.0 - sum(normalized_changes) / len(normalized_changes))

        cf = CounterfactualExplanation(
            decision_id=decision_id,
            original_instance=original,
            counterfactual_instance=dict(counterfactual),
            changed_features=list(changed),
            feature_changes={
                name: counterfactual[name] - original[name] for name in changed
            },
            outcome_change=(
                "fraud to non-fraud" if was_fraud else "non-fraud to fraud"
            ),
            proximity_score=round(proximity, 4),
            # High sparsity = few features changed
            sparsity_score=round(1.0 - len(changed) / max(len(original), 1), 4),
        )

        self._store.store_counterfactual(cf)
        return cf
