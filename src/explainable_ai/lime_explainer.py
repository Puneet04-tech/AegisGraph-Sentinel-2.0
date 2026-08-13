"""
LIME Explainer Module.

LIME (Local Interpretable Model-agnostic Explanations) implementation.
"""

import math
from typing import Callable, Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    Explanation,
    FeatureImportance,
    ExplanationType,
)
from .store import ExplainableAIStore, get_xai_store

logger = logging.getLogger(__name__)


class LIMEExplainer:
    """LIME Explainer for local model explanations.
    
    Provides:
        - Local linear approximation
        - Perturbation-based explanations
        - Feature weight analysis
        - Interpretable explanations
    """

    #: Relative offsets applied to a feature when probing the model around the
    #: instance being explained. Fixed rather than sampled so that explaining
    #: the same decision twice yields the same explanation -- an explanation
    #: that changes between runs cannot be audited.
    PERTURBATION_OFFSETS = (-0.5, -0.25, -0.1, 0.1, 0.25, 0.5)

    #: Width of the proximity kernel, as a fraction of the feature's own
    #: magnitude. Perturbations further than this contribute little.
    KERNEL_WIDTH = 0.5

    #: Absolute step used to probe a feature whose value is zero, where a
    #: relative offset would move nothing.
    ZERO_VALUE_STEP = 1.0

    def __init__(self, store: Optional[ExplainableAIStore] = None):
        """Initialize the LIME explainer."""
        self._store = store or get_xai_store()
        self._module_id = "lime_explainer"
        self._num_samples = len(self.PERTURBATION_OFFSETS)
    
    def explain(
        self,
        decision_id: str,
        model_id: str,
        model_version: str,
        input_features: Dict[str, float],
        prediction_value: float = 1.0,
        predict_fn: Optional[Callable[[Dict[str, float]], float]] = None,
    ) -> Explanation:
        """Generate LIME explanation for a decision.

        Args:
            predict_fn: The model being explained, as a callable taking a
                feature dict and returning a score. LIME is defined in terms
                of probing a model; without one, no local approximation is
                possible and the explanation falls back to a documented
                value attribution that is labelled as such.
        """
        logger.info(f"Generating LIME explanation for decision {decision_id}")

        # Fit a local linear approximation by probing the model around this
        # instance.
        feature_weights = self._compute_lime_weights(
            input_features, prediction_value, predict_fn,
        )
        model_based = predict_fn is not None
        
        # Create feature importance list
        feature_importances = [
            FeatureImportance(
                feature=feature,
                importance=weight,
                # A feature the model is flat on contributed nothing; calling
                # that "negative" misreads the explanation.
                direction=(
                    "positive" if weight > 0
                    else "negative" if weight < 0
                    else "neutral"
                ),
                confidence=abs(weight) / (sum(abs(w) for w in feature_weights.values()) + 0.001),
            )
            for feature, weight in feature_weights.items()
        ]
        
        # Sort by absolute importance
        sorted_features = sorted(feature_importances, key=lambda x: abs(x.importance), reverse=True)
        top_features = [f.feature for f in sorted_features[:5]]
        
        # Calculate confidence
        total_weight = sum(abs(w) for w in feature_weights.values())
        confidence = min(1.0, total_weight / len(feature_weights)) if feature_weights else 0.5
        
        # Create explanation
        explanation = Explanation(
            decision_id=decision_id,
            explanation_type=ExplanationType.LIME,
            model_id=model_id,
            model_version=model_version,
            features=sorted_features,
            base_value=0.0,
            prediction_value=prediction_value,
            confidence=confidence,
            summary=self._generate_summary(sorted_features, prediction_value),
            top_contributing_features=top_features,
            metadata={
                # An explanation that was not derived from the model must say
                # so; previously every explanation claimed to be LIME.
                "method": "LIME" if model_based else "value_attribution",
                "model_based": model_based,
                "num_samples": (
                    self._num_samples * len(input_features) if model_based else 0
                ),
                "perturbation_offsets": list(self.PERTURBATION_OFFSETS),
            },
        )
        
        self._store.store_explanation(explanation)
        return explanation
    
    def _compute_lime_weights(
        self,
        features: Dict[str, float],
        prediction: float,
        predict_fn: Optional[Callable[[Dict[str, float]], float]] = None,
    ) -> Dict[str, float]:
        """Compute LIME weights by locally probing the model.

        The previous implementation never called a model. It perturbed each
        feature to ``value * random.uniform(0.5, 1.5)``, took a
        proximity-weighted mean of ``(perturbed - value)`` -- a quantity whose
        expectation is near zero and which carries no information about the
        model -- and then multiplied the result by a further
        ``random.uniform(0.8, 1.2)``. The output was noise wearing the label
        "LIME", and it differed on every call for the same decision.
        """
        if predict_fn is None:
            logger.warning(
                "No predict_fn supplied; falling back to value attribution "
                "rather than a local model approximation",
            )
            return self._value_attribution(features, prediction)

        weights = {}
        for feature, value in features.items():
            weights[feature] = self._local_slope(
                features, feature, value, predict_fn,
            )

        return weights

    def _local_slope(
        self,
        features: Dict[str, float],
        feature: str,
        value: float,
        predict_fn: Callable[[Dict[str, float]], float],
    ) -> float:
        """Weighted least-squares slope of the model along one feature.

        This is the local linear approximation LIME is defined by: probe the
        model at fixed offsets around the instance, weight each probe by its
        proximity to the original point, and fit a line.
        """
        step = abs(value) if value else self.ZERO_VALUE_STEP

        samples = []
        for offset in self.PERTURBATION_OFFSETS:
            perturbed_value = value + offset * step
            probe = dict(features)
            probe[feature] = perturbed_value

            try:
                outcome = float(predict_fn(probe))
            except Exception:
                # A model that cannot score this probe contributes nothing;
                # it must not take down the whole explanation.
                logger.warning(
                    "predict_fn failed while probing feature '%s'",
                    feature, exc_info=True,
                )
                continue

            # Gaussian proximity kernel over the perturbation distance.
            distance = abs(perturbed_value - value) / (step * self.KERNEL_WIDTH)
            samples.append((perturbed_value, outcome, math.exp(-distance ** 2)))

        if len(samples) < 2:
            return 0.0

        total_weight = sum(w for _, _, w in samples)
        if total_weight <= 0:
            return 0.0

        mean_x = sum(w * x for x, _, w in samples) / total_weight
        mean_y = sum(w * y for _, y, w in samples) / total_weight

        covariance = sum(w * (x - mean_x) * (y - mean_y) for x, y, w in samples)
        variance = sum(w * (x - mean_x) ** 2 for x, _, w in samples)

        if variance <= 0:
            # The model is flat along this feature here: no contribution.
            return 0.0

        # Report the effect of the feature's actual magnitude, not the slope
        # per unit, so weights are comparable across features on different
        # scales.
        return (covariance / variance) * step

    def _value_attribution(
        self,
        features: Dict[str, float],
        prediction: float,
    ) -> Dict[str, float]:
        """Deterministic fallback when there is no model to probe.

        Attributes the prediction across features in proportion to their
        magnitude. This is not a model explanation and is labelled
        ``value_attribution`` in the explanation metadata so it cannot be
        mistaken for one.
        """
        total = sum(abs(v) for v in features.values())
        if not total:
            return {feature: 0.0 for feature in features}

        return {
            feature: (value / total) * prediction
            for feature, value in features.items()
        }
    
    def _generate_summary(self, features: List[FeatureImportance], prediction: float) -> str:
        """Generate human-readable LIME summary."""
        if not features:
            return "No significant features identified"
        
        top_3 = features[:3]
        
        parts = ["Key factors influencing this decision:"]
        for feat in top_3:
            direction = "increased" if feat.importance > 0 else "decreased"
            parts.append(f"- {feat.feature} {direction} fraud probability by {abs(feat.importance):.2f}")
        
        risk = "HIGH" if prediction > 0.7 else "MEDIUM" if prediction > 0.4 else "LOW"
        parts.append(f"Predicted risk level: {risk}")
        
        return ". ".join(parts)
    
    def get_local_explanation(
        self,
        decision_id: str,
    ) -> Dict[str, Any]:
        """Get detailed local explanation."""
        explanation = self._store.get_decision_explanation(decision_id)
        
        if not explanation:
            return {"error": "Explanation not found"}
        
        return {
            "decision_id": decision_id,
            "explanation_type": explanation.explanation_type.value,
            "prediction": explanation.prediction_value,
            "confidence": explanation.confidence,
            "summary": explanation.summary,
            "feature_weights": {
                f.feature: {
                    "weight": f.importance,
                    "direction": f.direction,
                    "confidence": f.confidence,
                }
                for f in explanation.features
            },
            "top_features": explanation.top_contributing_features,
        }
    
    def compare_explanations(
        self,
        decision_id_1: str,
        decision_id_2: str,
    ) -> Dict[str, Any]:
        """Compare two LIME explanations."""
        exp1 = self._store.get_decision_explanation(decision_id_1)
        exp2 = self._store.get_decision_explanation(decision_id_2)
        
        if not exp1 or not exp2:
            return {"error": "One or both explanations not found"}
        
        # Find common and different features
        features1 = {f.feature: f.importance for f in exp1.features}
        features2 = {f.feature: f.importance for f in exp2.features}
        
        common_features = set(features1.keys()) & set(features2.keys())
        only_in_1 = set(features1.keys()) - set(features2.keys())
        only_in_2 = set(features2.keys()) - set(features1.keys())
        
        return {
            "decision_1": {
                "id": decision_id_1,
                "prediction": exp1.prediction_value,
            },
            "decision_2": {
                "id": decision_id_2,
                "prediction": exp2.prediction_value,
            },
            "common_features": list(common_features),
            "features_only_in_1": list(only_in_1),
            "features_only_in_2": list(only_in_2),
            "feature_difference": {
                f: features1[f] - features2[f]
                for f in common_features
            },
        }


# Global singleton
_lime_explainer: Optional[LIMEExplainer] = None


def get_lime_explainer(store: Optional[ExplainableAIStore] = None) -> LIMEExplainer:
    """Get or create the singleton LIMEExplainer instance."""
    global _lime_explainer
    
    if _lime_explainer is None:
        _lime_explainer = LIMEExplainer(store=store)
    return _lime_explainer