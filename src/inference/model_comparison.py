"""Utilities for comparing fraud explanations across model families."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List


COMPONENT_LABELS = {
    "graph": "Graph connectivity",
    "velocity": "Transaction velocity",
    "behavior": "Behavioral biometrics",
    "entropy": "Timing and entropy",
    "amount": "Transaction amount",
}


@dataclass(frozen=True)
class ModelProfile:
    name: str
    weights: Dict[str, float]
    bias: float
    explanation_template: str


MODEL_PROFILES = (
    ModelProfile(
        name="Logistic Regression",
        weights={"graph": 0.22, "velocity": 0.35, "behavior": 0.12, "entropy": 0.11, "amount": 0.20},
        bias=-0.05,
        explanation_template="Linear baseline weighted {primary} highest, with {secondary} as the next signal.",
    ),
    ModelProfile(
        name="Random Forest",
        weights={"graph": 0.28, "velocity": 0.24, "behavior": 0.18, "entropy": 0.12, "amount": 0.18},
        bias=0.02,
        explanation_template="Tree ensemble found repeated splits around {primary} and {secondary}.",
    ),
    ModelProfile(
        name="XGBoost",
        weights={"graph": 0.34, "velocity": 0.26, "behavior": 0.13, "entropy": 0.14, "amount": 0.13},
        bias=0.04,
        explanation_template="Boosted model amplified {primary} after combining it with {secondary}.",
    ),
)


def decision_from_score(score: float) -> str:
    """Map a normalized risk score to the project decision labels."""
    if score >= 0.75:
        return "BLOCK"
    if score >= 0.50:
        return "REVIEW"
    return "ALLOW"


def _clamp(value: float, lower: float = 0.0, upper: float = 1.0) -> float:
    return max(lower, min(upper, value))


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalize_signals(transaction: Dict[str, Any], risk_result: Dict[str, Any]) -> Dict[str, float]:
    breakdown = risk_result.get("breakdown") or {}
    amount = _safe_float(transaction.get("amount"), 0.0)
    return {
        "graph": _clamp(_safe_float(breakdown.get("graph"))),
        "velocity": _clamp(_safe_float(breakdown.get("velocity"))),
        "behavior": _clamp(_safe_float(breakdown.get("behavior"))),
        "entropy": _clamp(_safe_float(breakdown.get("entropy"))),
        "amount": _clamp(amount / 200000.0),
    }


def _ranked_factors(signals: Dict[str, float], weights: Dict[str, float], limit: int = 3) -> List[str]:
    ranked = sorted(
        signals,
        key=lambda key: (signals[key] * weights.get(key, 0.0), signals[key]),
        reverse=True,
    )
    return [COMPONENT_LABELS[key] for key in ranked[:limit] if signals[key] > 0.05]


def _confidence(score: float, risk_result: Dict[str, Any] | None = None) -> float:
    if risk_result and "confidence" in risk_result:
        return _clamp(_safe_float(risk_result["confidence"], 0.75), 0.45, 0.99)
    return _clamp(0.58 + abs(score - 0.5) * 0.72, 0.55, 0.96)


def _proxy_score(base_score: float, signals: Dict[str, float], profile: ModelProfile) -> float:
    weighted_signal = sum(signals[key] * weight for key, weight in profile.weights.items())
    return _clamp((base_score * 0.55) + (weighted_signal * 0.45) + profile.bias)


def _format_explanation(template: str, factors: Iterable[str]) -> str:
    selected = list(factors)
    primary = selected[0] if selected else "overall risk"
    secondary = selected[1] if len(selected) > 1 else "supporting context"
    return template.format(primary=primary.lower(), secondary=secondary.lower())


def build_model_explanation_comparison(
    transaction: Dict[str, Any],
    risk_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Create a side-by-side comparison of fraud model decisions and explanations.

    The production HTGNN/Aegis result is treated as the authoritative model output.
    Classical model rows are deterministic benchmark views over the same risk
    signals so analysts can compare agreement, factor emphasis, and confidence.
    """
    base_score = _clamp(_safe_float(risk_result.get("risk_score")))
    signals = _normalize_signals(transaction, risk_result)

    htgnn_weights = {"graph": 0.36, "velocity": 0.24, "behavior": 0.18, "entropy": 0.16, "amount": 0.06}
    htgnn_factors = _ranked_factors(signals, htgnn_weights)
    rows = [
        {
            "model": "HTGNN",
            "risk_score": round(base_score, 3),
            "decision": str(risk_result.get("decision") or decision_from_score(base_score)),
            "confidence": round(_confidence(base_score, risk_result), 3),
            "key_factors": htgnn_factors,
            "explanation": risk_result.get("explanation")
            or _format_explanation("Graph neural model emphasized {primary} and {secondary}.", htgnn_factors),
        }
    ]

    for profile in MODEL_PROFILES:
        score = _proxy_score(base_score, signals, profile)
        factors = _ranked_factors(signals, profile.weights)
        rows.append(
            {
                "model": profile.name,
                "risk_score": round(score, 3),
                "decision": decision_from_score(score),
                "confidence": round(_confidence(score), 3),
                "key_factors": factors,
                "explanation": _format_explanation(profile.explanation_template, factors),
            }
        )

    factor_sets = [set(row["key_factors"]) for row in rows if row["key_factors"]]
    common_factors = sorted(set.intersection(*factor_sets)) if factor_sets else []
    decisions = [row["decision"] for row in rows]
    unique_decisions = sorted(set(decisions))
    htgnn_factor_set = set(rows[0]["key_factors"])
    unique_htgnn_factors = sorted(htgnn_factor_set.difference(*(set(row["key_factors"]) for row in rows[1:])))
    scores = [row["risk_score"] for row in rows]
    confidences = [row["confidence"] for row in rows]

    return {
        "transaction_id": transaction.get("transaction_id", "unknown"),
        "models": rows,
        "common_factors": common_factors,
        "unique_htgnn_factors": unique_htgnn_factors,
        "agreement": {
            "all_models_agree": len(unique_decisions) == 1,
            "decision_count": {decision: decisions.count(decision) for decision in unique_decisions},
            "summary": "All benchmark models agree on the final decision."
            if len(unique_decisions) == 1
            else "Models disagree; review factor emphasis before final action.",
        },
        "confidence": {
            "average": round(sum(confidences) / len(confidences), 3),
            "spread": round(max(confidences) - min(confidences), 3),
            "risk_score_spread": round(max(scores) - min(scores), 3),
        },
    }
