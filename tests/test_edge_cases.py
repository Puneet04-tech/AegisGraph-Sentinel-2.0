from src.scoring import EdgeCaseHandler, RiskScorer
import math
  

def test_edge_case_handler_safe_score_and_weights():
    assert EdgeCaseHandler.safe_score(None) == 0.0
    assert EdgeCaseHandler.safe_score(float("nan")) == 0.0
    assert EdgeCaseHandler.safe_score(float("inf")) == 0.0

    weights = EdgeCaseHandler.safe_weights({"a": 0.0, "b": 0.0}, keys=["a", "b"])
    assert weights["a"] == 0.5
    assert weights["b"] == 0.5

    safe_weights = EdgeCaseHandler.safe_weights({"a": 2.0, "b": -1.0}, keys=["a", "b"])
    assert math.isclose(safe_weights["a"], 1.0)
    assert math.isclose(safe_weights["b"], 0.0)


def test_detect_circular_transfers_in_transaction_history():
    transactions = [
        {"source_account": "A", "target_account": "B"},
        {"source_account": "B", "target_account": "C"},
        {"source_account": "C", "target_account": "A"},
    ]
    cycles = EdgeCaseHandler.detect_circular_transfers(transactions)
    assert cycles
    assert any(set(cycle) == {"A", "B", "C"} for cycle in cycles)
    assert EdgeCaseHandler.has_circular_transfers(transactions)


def test_safe_components_non_dict_returns_empty():
    assert EdgeCaseHandler.safe_components(None) == {}
    assert EdgeCaseHandler.safe_components("not a dict") == {}


def test_risk_scorer_metadata_marks_circular_transfers():
    transactions = [
        {"source_account": "A", "target_account": "B"},
        {"source_account": "B", "target_account": "A"},
    ]
    scorer = RiskScorer(component_weights={"graph": 0.5, "velocity": 0.5})
    assessment = scorer.assess({"graph": 0.4, "velocity": 0.3}, metadata={"transactions": transactions})
    assert assessment.metadata.get("circular_transfers") is True


def test_detect_circular_transfers_no_duplicate_cycles():
    transactions = [
        {"source_account": "A", "target_account": "B"},
        {"source_account": "B", "target_account": "C"},
        {"source_account": "C", "target_account": "A"},
    ]
    cycles = EdgeCaseHandler.detect_circular_transfers(transactions)
    assert len(cycles) == 1 