"""
Red Team Agent
AegisGraph Sentinel - Adversarial attack simulation for model robustness.

Simulates sophisticated attacker behaviours (slow drip transactions,
structured amount evasion, entity hopping across namespaces) and benchmarks
a scoring model against a library of known evasion techniques to surface
model blind spots.
"""

from __future__ import annotations

import random
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

from .models import AttackPattern, EvasionReport

EVASION_TECHNIQUES: List[Dict[str, Any]] = [
    {"name": "slow_drip", "target": "velocity", "description": "Small frequent transfers under threshold"},
    {"name": "structured_amounts", "target": "amount", "description": "Amounts just below reporting thresholds"},
    {"name": "entity_hopping", "target": "identity", "description": "Fresh accounts relay funds quickly"},
    {"name": "fan_out", "target": "counterparty", "description": "One account disburses to many"},
    {"name": "fan_in", "target": "counterparty", "description": "Many accounts converge on accumulator"},
    {"name": "smurfing", "target": "amount", "description": "Large amount split into many small parts"},
    {"name": "off_hours_activity", "target": "temporal", "description": "Activity in human-review dead hours"},
    {"name": "round_trip", "target": "topology", "description": "Funds cycle back through intermediaries"},
    {"name": "identity_churn", "target": "identity", "description": "Reused synthetic identities across fleet"},
    {"name": "gradual_escalation", "target": "velocity", "description": "Slow velocity ramp to look organic"},
]

DETECTION_THRESHOLD = 0.5


class RedTeamAgent:
    """Red team agent that stress-tests a fraud scoring model.

    A model is any callable ``model(features: dict) -> float`` returning a
    risk score in ``[0, 1]``. The red team perturbs baseline features per
    technique and treats a low score on the perturbed sample as evasion.
    """

    def __init__(self, model: Optional[Callable[[Dict[str, float]], float]] = None, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed)
        self._model = model or self._default_model
        self._reports: List[EvasionReport] = []
        self._generated_patterns: List[AttackPattern] = []

    def run_benchmark(self, samples_per_technique: int = 25) -> List[EvasionReport]:
        """Benchmark the model against all known evasion techniques.

        Returns:
            List of EvasionReport, one per technique in EVASION_TECHNIQUES.
        """
        reports: List[EvasionReport] = []
        for technique in EVASION_TECHNIQUES:
            detected = 0
            for _ in range(samples_per_technique):
                features = self._build_adversarial_features(technique["name"])
                score = self._score(features)
                if score >= DETECTION_THRESHOLD:
                    detected += 1
            samples = samples_per_technique
            evasion_rate = 1.0 - (detected / samples if samples else 0.0)
            report = EvasionReport(
                technique=technique["name"],
                samples=samples,
                detected=detected,
                evasion_rate=round(evasion_rate, 4),
                blind_spot=evasion_rate >= 0.5,
                details={
                    "description": technique["description"],
                    "target": technique["target"],
                },
            )
            reports.append(report)
            self._reports.append(report)
        return reports

    def identify_blind_spots(self, benchmark: Optional[List[EvasionReport]] = None) -> List[EvasionReport]:
        """Return the techniques where adversarial patterns evaded detection."""
        reports = benchmark if benchmark is not None else self._reports
        return [r for r in reports if r.blind_spot]

    def generate_attack_patterns(self) -> List[AttackPattern]:
        """Materialize red team techniques as attack patterns for the store."""
        patterns = []
        for technique in EVASION_TECHNIQUES:
            pattern = AttackPattern(
                pattern_id=f"redteam-{uuid4().hex[:12]}",
                name=f"Red Team: {technique['name'].replace('_', ' ').title()}",
                technique=technique["name"],
                tactics=["defense_evasion"],
                entity_type="account",
                temporal_context="short_burst",
                indicators=[technique["name"]],
                detections={"blind_spot": self._is_blind_spot(technique["name"])},
                ttp_reference=technique["name"],
            )
            patterns.append(pattern)
            self._generated_patterns.append(pattern)
        return patterns

    # ------------------------------------------------------------------
    # Model interaction
    # ------------------------------------------------------------------

    def _score(self, features: Dict[str, float]) -> float:
        try:
            value = float(self._model(features))
        except Exception:  # noqa: BLE001 - a broken model counts as a blind spot
            return 0.0
        return max(0.0, min(1.0, value))

    _TECHNIQUE_PROFILES: Dict[str, Dict[str, float]] = {
        "slow_drip": {"amount": 60.0, "frequency": 0.8},
        "structured_amounts": {"amount": 950.0},
        "entity_hopping": {"account_age_days": 5.0, "counterparty_count": 14.0},
        "fan_out": {"counterparty_count": 25.0},
        "fan_in": {"amount": 150.0, "counterparty_count": 20.0},
        "smurfing": {"amount": 50.0, "frequency": 0.9},
        "off_hours_activity": {"velocity": 1.0},
        "round_trip": {"amount": 550.0},
        "identity_churn": {"account_age_days": 10.0},
        "gradual_escalation": {"velocity": 1.5},
    }

    def _build_adversarial_features(self, technique: str) -> Dict[str, float]:
        """Build an adversarial feature vector tuned to dodge detection."""
        base = {
            "amount": self._rng.uniform(50.0, 900.0),
            "velocity": self._rng.uniform(0.5, 3.0),
            "account_age_days": self._rng.uniform(90.0, 900.0),
            "counterparty_count": self._rng.uniform(1.0, 8.0),
            "frequency": self._rng.uniform(0.1, 1.0),
        }
        profile = self._TECHNIQUE_PROFILES.get(technique, {})
        for key, value in profile.items():
            base[key] = value
        return base

    def _is_blind_spot(self, technique: str) -> bool:
        for report in self._reports:
            if report.technique == technique:
                return report.blind_spot
        return False

    @staticmethod
    def _default_model(features: Dict[str, float]) -> float:
        """A weak baseline model that misses sophisticated evasion."""
        score = 0.3
        if features.get("velocity", 0.0) > 8.0:
            score += 0.4
        if features.get("amount", 0.0) > 1000.0:
            score += 0.3
        return min(1.0, score)
