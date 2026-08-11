from typing import Dict, Optional

from .edge_cases import EdgeCaseHandler
from .risk_model import RiskAssessment, RiskBreakdown
from .threshold_config import ThresholdConfig


class ScoreCalculator:
    """Core score aggregation and confidence utilities."""

    @staticmethod
    def normalize_score(value: float, min_value: float = 0.0, max_value: float = 1.0) -> float:
        if max_value == min_value:
            return 0.0

        raw_value = EdgeCaseHandler.safe_float(value, default=min_value, min_value=min_value, max_value=max_value)
        normalized = (raw_value - min_value) / (max_value - min_value)
        return EdgeCaseHandler.safe_score(normalized)

    @staticmethod
    def aggregate_scores(
        component_scores: Dict[str, float],
        weights: Optional[Dict[str, float]] = None,
    ) -> float:
        safe_scores = EdgeCaseHandler.safe_components(component_scores)
        safe_weights = EdgeCaseHandler.safe_weights(weights, keys=safe_scores.keys())

        total = 0.0
        for name, score in safe_scores.items():
            weight = safe_weights.get(name, 0.0)
            total += score * weight

        return EdgeCaseHandler.safe_score(total)

    @staticmethod
    def compute_confidence(
        overall_score: float,
        breakdown: Optional[Dict[str, float]] = None,
    ) -> float:
        safe_overall = EdgeCaseHandler.safe_score(overall_score)
        if not breakdown:
            return safe_overall

        normalized_components = [EdgeCaseHandler.safe_score(value) for value in breakdown.values()]
        if not normalized_components:
            return safe_overall

        average_component = sum(normalized_components) / len(normalized_components)
        separation = 1.0 - abs(safe_overall - average_component)
        confidence = (safe_overall * 0.6) + (average_component * 0.3) + (separation * 0.1)
        return EdgeCaseHandler.safe_score(confidence)


class RiskScorer:
    """Stateless orchestration layer for centralized risk scoring."""

    def __init__(
        self,
        threshold_config: Optional[ThresholdConfig] = None,
        component_weights: Optional[Dict[str, float]] = None,
    ):
        self.threshold_config = threshold_config or ThresholdConfig()
        self.component_weights = component_weights

    def assess(
        self,
        component_scores: Dict[str, float],
        metadata: Optional[Dict[str, str]] = None,
    ) -> RiskAssessment:
        safe_scores = EdgeCaseHandler.safe_components(component_scores)

        if metadata and isinstance(metadata.get("transactions"), list):
            if EdgeCaseHandler.has_circular_transfers(metadata["transactions"]):
                metadata = dict(metadata)
                metadata["circular_transfers"] = True

        if self.component_weights:
            for key in self.component_weights.keys():
                safe_scores.setdefault(key, 0.5)

        weights = EdgeCaseHandler.safe_weights(self.component_weights, keys=safe_scores.keys())
        overall_score = ScoreCalculator.aggregate_scores(safe_scores, weights)
        confidence = ScoreCalculator.compute_confidence(overall_score, safe_scores)

        if metadata and metadata.get("circular_transfers"):
            confidence = max(0.0, confidence - 0.05)

        decision = self.threshold_config.decision_for_score(overall_score)

        return RiskAssessment(
            overall_score=overall_score,
            confidence=confidence,
            decision=decision,
            breakdown=RiskBreakdown(components=safe_scores),
            metadata=metadata or {},
        )
