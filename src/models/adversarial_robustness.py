"""
Adversarial Robustness Evaluation
AegisGraph Sentinel - Model robustness evaluation against simulated attacks.

Evaluates a fraud scoring model against simulated adversarial attacks and
computes a robustness score. The evaluator is model-agnostic: a model is any
callable ``model(features: dict) -> float`` returning a risk score in
``[0, 1]`` where higher means more likely fraudulent.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

DETECTION_THRESHOLD = 0.5

EVASION_TECHNIQUES = [
    "slow_drip",
    "structured_amounts",
    "entity_hopping",
    "fan_out",
    "fan_in",
    "smurfing",
    "off_hours_activity",
    "round_trip",
    "identity_churn",
    "gradual_escalation",
]


class AdversarialRobustnessEvaluator:
    """Evaluates model robustness against simulated adversarial attacks.

    Attributes:
        model: Callable scoring model.
        detection_threshold: Risk score at or above which an attack is
            considered detected.
    """

    def __init__(
        self,
        model: Optional[Callable[[Dict[str, float]], float]] = None,
        detection_threshold: float = DETECTION_THRESHOLD,
    ) -> None:
        self.model = model or self._baseline_model
        self.detection_threshold = detection_threshold
        self._reports: List[Dict[str, Any]] = []

    def evaluate(self, samples_per_technique: int = 25) -> Dict[str, Any]:
        """Run the evasion benchmark and produce a robustness report.

        Returns:
            Dict with ``robustness_score``, ``evasion_rate``,
            ``blind_spots``, ``technique_results`` and ``report_id``.
        """
        technique_results: List[Dict[str, Any]] = []
        blind_spots: List[str] = []
        total_detected = 0
        total_samples = 0

        for technique in EVASION_TECHNIQUES:
            detected = 0
            for _ in range(samples_per_technique):
                features = self._adversarial_features(technique)
                score = self._score(features)
                if score >= self.detection_threshold:
                    detected += 1
            total_detected += detected
            total_samples += samples_per_technique
            evasion_rate = 1.0 - (detected / samples_per_technique)
            result = {
                "technique": technique,
                "evasion_rate": round(evasion_rate, 4),
                "detected": detected,
                "blind_spot": evasion_rate >= 0.5,
            }
            technique_results.append(result)
            if result["blind_spot"]:
                blind_spots.append(technique)

        overall_evasion = 1.0 - (total_detected / total_samples if total_samples else 0.0)
        report = {
            "report_id": f"robustness-{uuid4().hex[:12]}",
            "robustness_score": round(1.0 - overall_evasion, 4),
            "evasion_rate": round(overall_evasion, 4),
            "blind_spots": blind_spots,
            "blind_spot_count": len(blind_spots),
            "technique_results": technique_results,
            "detection_threshold": self.detection_threshold,
        }
        self._reports.append(report)
        return report

    def compare_models(
        self,
        other_model: Callable[[Dict[str, float]], float],
        samples_per_technique: int = 25,
    ) -> Dict[str, Any]:
        """Compare robustness between the current and a candidate model."""
        self.model, candidate_model = self.model, other_model
        baseline_report = self.evaluate(samples_per_technique)

        original_model = self.model
        self.model = candidate_model
        candidate_report = self.evaluate(samples_per_technique)
        self.model = original_model

        baseline_score = baseline_report["robustness_score"]
        candidate_score = candidate_report["robustness_score"]
        return {
            "baseline_robustness": baseline_score,
            "candidate_robustness": candidate_score,
            "delta": round(candidate_score - baseline_score, 4),
            "candidate_blind_spots": candidate_report["blind_spots"],
            "recommendation": (
                "adopt candidate" if candidate_score > baseline_score
                else "retain baseline"
            ),
        }

    def get_reports(self) -> List[Dict[str, Any]]:
        return list(self._reports)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _score(self, features: Dict[str, float]) -> float:
        try:
            value = float(self.model(features))
        except Exception:  # noqa: BLE001 - unscoreable model counts as blind spot
            return 0.0
        return max(0.0, min(1.0, value))

    def _adversarial_features(self, technique: str) -> Dict[str, float]:
        """Craft features tuned to evade detection for the given technique."""
        base = {
            "amount": 500.0,
            "velocity": 2.0,
            "account_age_days": 300.0,
            "counterparty_count": 4.0,
            "frequency": 0.5,
        }
        perturbations: Dict[str, Dict[str, float]] = {
            "slow_drip": {"amount": 80.0, "frequency": 0.8},
            "structured_amounts": {"amount": 950.0},
            "entity_hopping": {"account_age_days": 3.0, "counterparty_count": 15.0},
            "fan_out": {"counterparty_count": 25.0},
            "fan_in": {"amount": 150.0, "counterparty_count": 20.0},
            "smurfing": {"amount": 40.0, "frequency": 0.9},
            "off_hours_activity": {"velocity": 1.0},
            "round_trip": {"amount": 600.0},
            "identity_churn": {"account_age_days": 5.0},
            "gradual_escalation": {"velocity": 1.5},
        }
        for key, value in perturbations.get(technique, {}).items():
            base[key] = value
        return base

    @staticmethod
    def _baseline_model(features: Dict[str, float]) -> float:
        score = 0.3
        if features.get("velocity", 0.0) > 8.0:
            score += 0.4
        if features.get("amount", 0.0) > 1000.0:
            score += 0.3
        return min(1.0, score)
