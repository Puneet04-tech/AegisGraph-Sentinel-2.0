"""
Unit tests for Automated Graph Counterfactual Explainer for Aegis-Oracle LLM (Issue #3459).
"""

import pytest
from src.inference.counterfactual_search import GraphCounterfactualSearchEngine
from src.features.aegis_oracle_explainer import AegisOracleExplainer


def test_counterfactual_search_engine_high_risk():
    engine = GraphCounterfactualSearchEngine(allow_threshold=0.70)
    transaction = {"transaction_id": "TXN-CF-100", "amount": 150000.0}
    risk_breakdown = {"graph": 0.85, "velocity": 0.90, "behavior": 0.88}

    result = engine.search_minimal_counterfactual(
        transaction=transaction,
        risk_score=0.92,
        risk_breakdown=risk_breakdown,
    )

    assert result["counterfactual_found"] is True
    assert result["counterfactual_risk_score"] < 0.70
    assert len(result["recommended_modifications"]) > 0
    assert "recourse_narrative" in result


def test_counterfactual_search_engine_already_allowed():
    engine = GraphCounterfactualSearchEngine(allow_threshold=0.70)
    transaction = {"transaction_id": "TXN-CF-101", "amount": 5000.0}

    result = engine.search_minimal_counterfactual(
        transaction=transaction,
        risk_score=0.25,
    )

    assert result["counterfactual_found"] is False
    assert "already allowed" in result["recourse_narrative"].lower()


def test_aegis_oracle_counterfactual_explanation():
    explainer = AegisOracleExplainer()
    transaction = {"transaction_id": "TXN-ORACLE-500", "amount": 250000.0}
    risk_assessment = {"decision": "BLOCK", "risk_score": 0.95, "breakdown": {"velocity": 0.90, "behavior": 0.85}}

    explanation = explainer.generate_counterfactual_explanation(
        transaction=transaction,
        risk_assessment=risk_assessment,
    )

    assert explanation["transaction_id"] == "TXN-ORACLE-500"
    assert explanation["original_decision"] == "BLOCK"
    assert "counterfactual" in explanation
    assert explanation["counterfactual"]["counterfactual_found"] is True
