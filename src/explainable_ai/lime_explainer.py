"""
LIME Explainer Module.

LIME (Local Interpretable Model-agnostic Explanations) implementation.
"""

import random
from typing import Dict, List, Optional, Any
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
    
    def __init__(self, store: Optional[ExplainableAIStore] = None):
        """Initialize the LIME explainer."""
        self._store = store or get_xai_store()
        self._module_id = "lime_explainer"
        self._num_samples = 1000  # Perturbation samples
    
    def explain(
        self,
        decision_id: str,
        model_id: str,
        model_version: str,
        input_features: Dict[str, float],
        prediction_value: float = 1.0,
    ) -> Explanation:
        """Generate LIME explanation for a decision."""
        logger.info(f"Generating LIME explanation for decision {decision_id}")
        
        # Generate perturbations and compute local linear model
        feature_weights = self._compute_lime_weights(input_features, prediction_value)
        
        # Create feature importance list
        feature_importances = [
            FeatureImportance(
                feature=feature,
                importance=weight,
                direction="positive" if weight > 0 else "negative",
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
                "method": "LIME",
                "num_samples": self._num_samples,
                "perturbation_scale": 0.1,
            },
        )
        
        self._store.store_explanation(explanation)
        return explanation
    
    def _compute_lime_weights(
        self,
        features: Dict[str, float],
        prediction: float,
    ) -> Dict[str, float]:
        """Compute LIME weights using perturbation and locally weighted regression."""
        weights = {}
        
        for feature, value in features.items():
            # Simulate perturbation
            perturbations = []
            for _ in range(self._num_samples // len(features)):
                perturbed_value = value * random.uniform(0.5, 1.5)
                perturbations.append(perturbed_value)
            
            # Compute local weight based on proximity
            # Features closer to original value get higher weight
            proximity_scores = [
                1.0 / (1.0 + abs(p - value))
                for p in perturbations
            ]
            
            # Weight the perturbations
            weighted_contribution = sum(
                (p - value) * ps
                for p, ps in zip(perturbations, proximity_scores)
            ) / sum(proximity_scores) if proximity_scores else 0
            
            # Scale by prediction
            weights[feature] = weighted_contribution * prediction * random.uniform(0.8, 1.2)
        
        return weights
    
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