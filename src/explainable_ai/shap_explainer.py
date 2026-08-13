"""
SHAP Explainer Module.

SHAP (SHapley Additive exPlanations) implementation for model explanations.
"""

import math
from typing import Callable, Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .counterfactual_generator import CounterfactualGenerator
from .models import (
    Explanation,
    FeatureImportance,
    ExplanationType,
    CounterfactualExplanation,
)
from .store import ExplainableAIStore, get_xai_store

logger = logging.getLogger(__name__)


class SHAPExplainer:
    """SHAP Explainer for model explanations.
    
    Provides:
        - SHAP value computation
        - Feature attribution
        - Local explanations
        - Global explanations
    """
    
    def __init__(
        self,
        store: Optional[ExplainableAIStore] = None,
        predict_fn: Optional[Callable[[Dict[str, float]], float]] = None,
        decision_threshold: float = 0.5,
    ):
        """Initialize the SHAP explainer.

        Args:
            store: Explanation store (defaults to the shared singleton).
            predict_fn: Optional callable mapping a feature dict to a
                risk probability. When provided, counterfactuals are
                found by searching against the real model instead of
                the deterministic heuristic fallback.
            decision_threshold: Boundary used to define a decision flip.
        """
        self._store = store or get_xai_store()
        self._module_id = "shap_explainer"
        # Kept for attribution as well as counterfactuals: with a model in
        # hand, contributions can be measured by ablation instead of split by
        # a heuristic.
        self._predict_fn = predict_fn
        self._counterfactual_generator = (
            CounterfactualGenerator(
                predict_fn,
                threshold=decision_threshold,
                store=self._store,
            )
            if predict_fn is not None
            else None
        )
    
    def explain(
        self,
        decision_id: str,
        model_id: str,
        model_version: str,
        input_features: Dict[str, float],
        base_value: float = 0.0,
        prediction_value: float = 1.0,
    ) -> Explanation:
        """Generate SHAP explanation for a decision."""
        logger.info(f"Generating SHAP explanation for decision {decision_id}")
        
        # Compute SHAP-like values
        feature_importances = self._compute_shap_values(input_features, base_value, prediction_value)
        
        # Sort by absolute importance
        sorted_features = sorted(feature_importances, key=lambda x: abs(x.importance), reverse=True)
        
        # Create top contributing features list
        top_features = [f.feature for f in sorted_features[:5]]
        
        # Calculate confidence based on feature agreement
        confidence = self._calculate_confidence(sorted_features)
        
        # Create explanation
        explanation = Explanation(
            decision_id=decision_id,
            explanation_type=ExplanationType.SHAP,
            model_id=model_id,
            model_version=model_version,
            features=sorted_features,
            base_value=base_value,
            prediction_value=prediction_value,
            confidence=confidence,
            summary=self._generate_summary(sorted_features, prediction_value),
            top_contributing_features=top_features,
        )
        
        self._store.store_explanation(explanation)
        
        # Generate counterfactual explanation. A model that cannot be probed
        # must not cost the caller their explanation, which is already stored
        # by this point.
        try:
            self._generate_counterfactual(decision_id, input_features, prediction_value)
        except Exception:
            logger.warning(
                "Counterfactual generation failed for decision %s; the "
                "explanation itself is unaffected", decision_id, exc_info=True,
            )

        return explanation
    
    def _compute_shap_values(
        self,
        features: Dict[str, float],
        base_value: float,
        prediction_value: float,
    ) -> List[FeatureImportance]:
        """Compute SHAP-like values using approximation.

        The defining property of a SHAP attribution is additivity: the
        contributions must sum to ``prediction_value - base_value``. That is
        preserved here, but the split between features is no longer arbitrary.

        Previously each contribution was ``remaining_diff * weight *
        random.uniform(0.8, 1.2)`` with the last feature absorbing whatever
        was left over. Additivity held only because of that mop-up, the split
        was driven by a random draw, and per-feature ``confidence`` was itself
        ``random.uniform(0.85, 0.99)`` -- which then fed the explanation's
        overall confidence.
        """
        total_diff = prediction_value - base_value

        if not features:
            return []

        raw = self._raw_contributions(features, prediction_value)

        # Rescale so the contributions sum exactly to the gap between the base
        # value and the prediction (the efficiency axiom).
        raw_total = sum(raw.values())
        if raw_total:
            scaled = {f: v * total_diff / raw_total for f, v in raw.items()}
        else:
            # The model is flat, or every feature is zero: split evenly rather
            # than attributing the whole gap to one arbitrary feature.
            share = total_diff / len(features)
            scaled = {f: share for f in features}

        magnitude = sum(abs(v) for v in scaled.values())

        feature_importances = []
        for feature, contribution in scaled.items():
            feature_importances.append(FeatureImportance(
                feature=feature,
                importance=contribution,
                direction=(
                    "positive" if contribution > 0
                    else "negative" if contribution < 0
                    else "neutral"
                ),
                # How concentrated this attribution is, rather than a random
                # number. A feature carrying most of the explanation is one we
                # are more confident about.
                confidence=(
                    abs(contribution) / magnitude if magnitude else 0.0
                ),
            ))

        return feature_importances

    def _raw_contributions(
        self,
        features: Dict[str, float],
        prediction_value: float,
    ) -> Dict[str, float]:
        """Unnormalised per-feature contributions.

        With a model available these are measured by ablation: how far the
        prediction moves when the feature is dropped to the base value. Without
        one, contributions fall back to each feature's share of the total
        magnitude -- deterministic, and stated as an approximation.
        """
        if self._predict_fn is None:
            return {feature: abs(value) for feature, value in features.items()}

        contributions = {}
        for feature in features:
            ablated = dict(features)
            ablated[feature] = 0.0

            try:
                without = float(self._predict_fn(ablated))
            except Exception:
                logger.warning(
                    "predict_fn failed while ablating feature '%s'",
                    feature, exc_info=True,
                )
                contributions[feature] = 0.0
                continue

            contributions[feature] = prediction_value - without

        if not any(contributions.values()):
            # Ablation moved nothing; fall back rather than divide by zero.
            return {feature: abs(value) for feature, value in features.items()}

        return contributions
    
    def _calculate_confidence(self, features: List[FeatureImportance]) -> float:
        """Calculate explanation confidence."""
        if not features:
            return 0.0
        
        # Confidence based on feature agreement
        avg_confidence = sum(f.confidence for f in features) / len(features)
        
        # Penalize for too many negative importance features
        neg_ratio = sum(1 for f in features if f.importance < 0) / len(features)
        
        confidence = avg_confidence * (1 - neg_ratio * 0.2)
        return min(1.0, max(0.0, confidence))
    
    def _generate_summary(self, features: List[FeatureImportance], prediction_value: float) -> str:
        """Generate human-readable summary."""
        if not features:
            return "Unable to generate explanation"
        
        top_positive = [f for f in features if f.direction == "positive"][:3]
        top_negative = [f for f in features if f.direction == "negative"][:3]
        
        parts = []
        
        if top_positive:
            feature_names = ", ".join([f.feature for f in top_positive])
            parts.append(f"Strong positive factors: {feature_names}")
        
        if top_negative:
            feature_names = ", ".join([f.feature for f in top_negative])
            parts.append(f"Negative factors: {feature_names}")
        
        risk_level = "high" if prediction_value > 0.7 else "medium" if prediction_value > 0.4 else "low"
        parts.append(f"Overall risk assessment: {risk_level}")
        
        return ". ".join(parts)
    
    def _generate_counterfactual(
        self,
        decision_id: str,
        features: Dict[str, float],
        prediction_value: float,
    ) -> Optional[CounterfactualExplanation]:
        """Generate counterfactual explanation.

        With a predict_fn attached, runs a model-probing search for a
        minimal, verified decision flip. Without one, falls back to a
        deterministic heuristic (halve the largest features) whose
        scores are computed from the actual deltas, never invented.
        """
        if self._counterfactual_generator is not None:
            return self._counterfactual_generator.generate(decision_id, features)

        cf_instance = dict(features)
        changed_features = []

        largest_features = sorted(
            features.items(), key=lambda item: abs(item[1]), reverse=True
        )[:3]
        for feature, value in largest_features:
            cf_instance[feature] = value * 0.5
            changed_features.append(feature)

        if not changed_features:
            return None

        cf = CounterfactualExplanation(
            decision_id=decision_id,
            original_instance=features,
            counterfactual_instance=cf_instance,
            changed_features=changed_features,
            feature_changes={f: cf_instance[f] - features[f] for f in changed_features},
            outcome_change="fraud to non-fraud" if prediction_value > 0.5 else "non-fraud to fraud",
            # Each change halves a feature: normalized change of 0.5
            proximity_score=0.5,
            # High sparsity = few features changed
            sparsity_score=round(
                1.0 - len(changed_features) / max(len(features), 1), 4
            ),
        )

        self._store.store_counterfactual(cf)
        return cf
    
    def get_global_importance(
        self,
        model_id: str,
        num_samples: int = 100,
    ) -> List[FeatureImportance]:
        """Get global feature importance for a model."""
        logger.info(f"Computing global importance for model {model_id}")
        
        # Simulate global importance from recent explanations
        explanations = self._store.get_model_explanations(model_id, limit=num_samples)
        
        if not explanations:
            # This used to invent five features named feature_0..feature_4
            # with random importances. Those names do not exist in any model,
            # and a caller had no way to tell them from real ones.
            logger.warning(
                "No stored explanations for model %s; global importance is "
                "unavailable", model_id,
            )
            return []
        
        # Aggregate feature importance
        feature_totals: Dict[str, List[float]] = {}
        
        for exp in explanations:
            for feat in exp.features:
                if feat.feature not in feature_totals:
                    feature_totals[feat.feature] = []
                feature_totals[feat.feature].append(abs(feat.importance))
        
        # Compute average importance
        global_importance = []
        for feature, values in feature_totals.items():
            avg_importance = sum(values) / len(values)
            global_importance.append(FeatureImportance(
                feature=feature,
                importance=avg_importance,
                direction="mixed",
                confidence=min(1.0, len(values) / 10),
            ))
        
        return sorted(global_importance, key=lambda x: x.importance, reverse=True)
    
    def explain_batch(
        self,
        decisions: List[Dict[str, Any]],
    ) -> List[Explanation]:
        """Generate explanations for multiple decisions."""
        explanations = []
        
        for decision in decisions:
            exp = self.explain(
                decision_id=decision["decision_id"],
                model_id=decision["model_id"],
                model_version=decision["model_version"],
                input_features=decision["features"],
                base_value=decision.get("base_value", 0.0),
                prediction_value=decision["prediction"],
            )
            explanations.append(exp)
        
        return explanations


# Global singleton
_shap_explainer: Optional[SHAPExplainer] = None


def get_shap_explainer(store: Optional[ExplainableAIStore] = None) -> SHAPExplainer:
    """Get or create the singleton SHAPExplainer instance."""
    global _shap_explainer
    
    if _shap_explainer is None:
        _shap_explainer = SHAPExplainer(store=store)
    return _shap_explainer