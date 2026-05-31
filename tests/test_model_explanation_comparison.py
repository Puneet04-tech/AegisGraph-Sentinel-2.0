from pathlib import Path

from src.inference.model_comparison import (
    build_model_explanation_comparison,
    decision_from_score,
)


def _sample_transaction():
    return {
        "transaction_id": "TXN123456",
        "source_account": "ACC_SOURCE",
        "target_account": "ACC_TARGET",
        "amount": 125000,
        "currency": "INR",
        "mode": "UPI",
    }


def _sample_risk_result():
    return {
        "risk_score": 0.82,
        "decision": "BLOCK",
        "confidence": 0.91,
        "breakdown": {
            "graph": 0.88,
            "velocity": 0.77,
            "behavior": 0.43,
            "entropy": 0.69,
        },
        "explanation": "High graph risk and transaction velocity detected.",
    }


def test_decision_from_score_uses_project_thresholds():
    assert decision_from_score(0.12) == "ALLOW"
    assert decision_from_score(0.50) == "REVIEW"
    assert decision_from_score(0.75) == "BLOCK"


def test_model_explanation_comparison_returns_side_by_side_models():
    comparison = build_model_explanation_comparison(_sample_transaction(), _sample_risk_result())

    model_names = [row["model"] for row in comparison["models"]]
    assert model_names == ["HTGNN", "Logistic Regression", "Random Forest", "XGBoost"]
    assert comparison["transaction_id"] == "TXN123456"
    assert comparison["agreement"]["decision_count"]
    assert 0 <= comparison["confidence"]["spread"] <= 1

    for row in comparison["models"]:
        assert 0 <= row["risk_score"] <= 1
        assert row["decision"] in {"ALLOW", "REVIEW", "BLOCK"}
        assert row["key_factors"]
        assert row["explanation"]


def test_model_explanation_comparison_dashboard_is_wired_into_streamlit_app():
    source = Path("app.py").read_text(encoding="utf-8")

    assert "build_model_explanation_comparison" in source
    assert "_render_model_explanation_comparison(transaction, result)" in source
    assert "Multi-Model Fraud Explanation Comparison" in source
