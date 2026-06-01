from typing import Dict, Optional

from .edge_cases import EdgeCaseHandler


DEFAULT_RISK_THRESHOLDS = {
    "allow": 0.0,
    "review": 0.6,
    "block": 0.9,
}


class ThresholdConfig:
    """Configuration manager for risk thresholds and decisions."""

    def __init__(self, thresholds: Optional[Dict[str, float]] = None):
        self.thresholds = dict(DEFAULT_RISK_THRESHOLDS)
        if thresholds:
            self.thresholds.update(thresholds)
        self._validate_thresholds()

    def _validate_thresholds(self) -> None:
        allow = EdgeCaseHandler.safe_score(self.thresholds.get("allow", 0.0))
        review = EdgeCaseHandler.safe_score(self.thresholds.get("review", 0.6))
        block = EdgeCaseHandler.safe_score(self.thresholds.get("block", 0.9))

        if not (0.0 <= allow < review < block <= 1.0):
            self.thresholds = dict(DEFAULT_RISK_THRESHOLDS)
            allow = DEFAULT_RISK_THRESHOLDS["allow"]
            review = DEFAULT_RISK_THRESHOLDS["review"]
            block = DEFAULT_RISK_THRESHOLDS["block"]

        self.thresholds["allow"] = allow
        self.thresholds["review"] = review
        self.thresholds["block"] = block

    def get_threshold(self, label: str, default: Optional[float] = None) -> Optional[float]:
        return self.thresholds.get(label, default)

    def decision_for_score(self, score: float) -> str:
        safe_score = EdgeCaseHandler.safe_score(score)
        block = self.thresholds["block"]
        review = self.thresholds["review"]

        if safe_score >= block:
            return "BLOCK"
        if safe_score >= review:
            return "REVIEW"
        return "ALLOW"

    @classmethod
    def from_dict(cls, thresholds: Dict[str, float]) -> "ThresholdConfig":
        return cls(thresholds=thresholds)
