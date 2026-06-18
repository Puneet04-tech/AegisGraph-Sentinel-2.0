from unittest.mock import Mock
import torch

from src.inference.risk_scorer import RiskScorer


def create_test_scorer():
    model = Mock()
    model.to.return_value = model
    model.eval.return_value = None

    config = {
        "risk_scoring": {
            "weights": {
                "graph": 0.5,
                "velocity": 0.2,
                "behavior": 0.2,
                "entropy": 0.1,
            }
        }
    }

    return RiskScorer(
        model=model,
        config=config,
        device=torch.device("cpu"),
    )


def test_risk_score_response_structure():
    scorer = create_test_scorer()

    result = scorer.compute_risk_score(
        transaction_data={
            "transaction_id": "TEST_001",
            "source_account": "USR001",
            "target_account": "MER001",
            "amount": 1000,
        }
    )

    assert "risk_score" in result
    assert "decision" in result
    assert "confidence" in result
    assert "breakdown" in result


def test_normal_transaction_generates_valid_score():
    scorer = create_test_scorer()

    result = scorer.compute_risk_score(
        transaction_data={
            "transaction_id": "NORMAL_001",
            "source_account": "USR001",
            "target_account": "MER001",
            "amount": 500,
        }
    )

    assert 0.0 <= result["risk_score"] <= 1.0


def test_risk_score_contains_all_components():
    scorer = create_test_scorer()

    result = scorer.compute_risk_score(
        transaction_data={
            "transaction_id": "TEST_002",
            "source_account": "USR002",
            "target_account": "MER002",
            "amount": 1000,
        }
    )

    breakdown = result["breakdown"]

    assert "graph" in breakdown
    assert "velocity" in breakdown
    assert "behavior" in breakdown
    assert "entropy" in breakdown