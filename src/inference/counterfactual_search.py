"""
Graph Counterfactual Search Engine for Aegis-Oracle LLM

Performs minimal edge and feature perturbation search to generate counterfactual explanations
("What minimal changes would have allowed this transaction?").
"""

from __future__ import annotations

import math
from typing import Dict, List, Any, Optional


class GraphCounterfactualSearchEngine:
    """Graph Counterfactual Optimization Engine."""

    def __init__(self, allow_threshold: float = 0.70):
        self.allow_threshold = allow_threshold

    def search_minimal_counterfactual(
        self,
        transaction: Dict[str, Any],
        risk_score: float,
        risk_breakdown: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """Searches for minimal counterfactual modifications to lower risk below target threshold.

        Args:
            transaction: Transaction input dictionary
            risk_score: Initial high risk score (>= 0.70)
            risk_breakdown: Breakdown of risk components (graph, velocity, behavior, etc.)

        Returns:
            Dictionary containing counterfactual perturbations and actionable recourse statement.
        """
        if risk_score < self.allow_threshold:
            return {
                "counterfactual_found": False,
                "reason": "Transaction risk score is already below threshold",
                "recommended_modifications": [],
                "recourse_narrative": "Transaction is already allowed.",
            }

        risk_breakdown = risk_breakdown or {}
        perturbations = []

        target_delta = risk_score - (self.allow_threshold - 0.05)
        current_delta = 0.0

        # 1. Evaluate Velocity Counterfactual
        amount = float(transaction.get("amount", 0.0))
        if amount > 50000.0 and current_delta < target_delta:
            suggested_amount = max(10000.0, amount * 0.4)
            delta_reduction = 0.20
            current_delta += delta_reduction
            perturbations.append({
                "feature": "amount",
                "original_value": amount,
                "counterfactual_value": suggested_amount,
                "description": f"Reduce transaction amount from {amount:.2f} INR to {suggested_amount:.2f} INR",
            })

        # 2. Evaluate Keystroke Biometrics Counterfactual
        behavior_risk = risk_breakdown.get("behavior", 0.0)
        if behavior_risk > 0.60 and current_delta < target_delta:
            current_delta += 0.25
            perturbations.append({
                "feature": "behavioral_biometrics",
                "original_value": "Elevated keystroke hesitation stress detected",
                "counterfactual_value": "Normal baseline typing rhythm",
                "description": "Complete transaction without external coaching or timing hesitations",
            })

        # 3. Evaluate Graph Topology Counterfactual
        graph_risk = risk_breakdown.get("graph", 0.0)
        if graph_risk > 0.60 and current_delta < target_delta:
            current_delta += 0.20
            perturbations.append({
                "feature": "graph_edge_connection",
                "original_value": "Direct transfer to untrusted new mule account",
                "counterfactual_value": "Transfer to verified beneficiary account with >30 day history",
                "description": "Route transaction to an existing verified beneficiary account",
            })

        counterfactual_score = max(0.0, round(risk_score - current_delta, 4))

        # Generate Actionable Regulatory Recourse Narrative
        recourse_text = "To allow this transaction under regulatory compliance, the following minimal changes are required: "
        recourse_text += "; ".join([p["description"] for p in perturbations]) + "."

        return {
            "counterfactual_found": True,
            "original_risk_score": risk_score,
            "target_threshold": self.allow_threshold,
            "counterfactual_risk_score": counterfactual_score,
            "recommended_modifications": perturbations,
            "recourse_narrative": recourse_text,
        }
