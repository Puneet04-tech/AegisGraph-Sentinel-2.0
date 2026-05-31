"""Regression tests for fraud pattern detection bounds."""

from datetime import datetime, timezone

import pytest

nx = pytest.importorskip("networkx")

from src.features.fraud_pattern_detector import FraudPatternDetector


def _make_transactions(edges):
    return [
        {
            "source_account": source,
            "target_account": target,
            "amount": 100,
            "timestamp": index,
        }
        for index, (source, target) in enumerate(edges)
    ]


def test_get_chain_transactions_indexed_lookup():
    """_get_chain_transactions builds an index for O(1) lookups instead of linear scans."""
    import networkx as nx
    detector = FraudPatternDetector()
    transactions = _make_transactions([
        ("A", "B"),
        ("B", "C"),
        ("C", "D"),
        ("A", "B"),  # duplicate edge
        ("X", "Y"),
    ])

    g = nx.DiGraph()
    g.add_edges_from([("A", "B"), ("B", "C"), ("C", "D")])

    chain = ["A", "B", "C", "D"]
    result = detector._get_chain_transactions(chain, g, transactions)
    assert len(result) == 4  # A->B (2) + B->C (1) + C->D (1)
    assert all(t["source_account"] in ("A", "B", "C") for t in result)
    assert all(t["target_account"] in ("B", "C", "D") for t in result)
def test_detect_fan_in_hubs_incremental_aggregation():
    """Fan-in detection uses incremental aggregation, no repeated list traversals."""
    detector = FraudPatternDetector()
    transactions = [
        {
            "source_account": f"source_{i}",
            "target_account": "hub_account",
            "amount": 100.0 + i,
            "timestamp": i,
        }
        for i in range(10)
    ]

    hubs = detector.detect_fan_in_hubs(transactions, threshold_incoming=5)
    assert len(hubs) == 1
    hub = hubs[0]
    assert hub["account"] == "hub_account"
    assert hub["incoming_transfer_count"] == 10
    assert hub["unique_sources"] == 10
    assert hub["total_received"] == sum(100.0 + i for i in range(10))
    assert hub["avg_transfer_amount"] == pytest.approx((sum(100.0 + i for i in range(10))) / 10)


def test_detect_fan_out_hubs_incremental_aggregation():
    """Fan-out detection uses incremental aggregation, no repeated list traversals."""
    detector = FraudPatternDetector()
    transactions = [
        {
            "source_account": "hub_account",
            "target_account": f"target_{i}",
            "amount": 200.0 + i,
            "timestamp": i,
        }
        for i in range(15)
    ]

    hubs = detector.detect_fan_out_hubs(transactions, threshold_outgoing=10)
    assert len(hubs) == 1
    hub = hubs[0]
    assert hub["account"] == "hub_account"
    assert hub["outgoing_transfer_count"] == 15
    assert hub["unique_targets"] == 15
    assert hub["total_distributed"] == sum(200.0 + i for i in range(15))
    assert hub["avg_transfer_amount"] == pytest.approx((sum(200.0 + i for i in range(15))) / 15)


def test_detect_fan_out_hubs_respects_threshold():
    """Fan-out detection correctly filters below threshold."""
    detector = FraudPatternDetector()
    transactions = [
        {"source_account": s, "target_account": "t", "amount": 100, "timestamp": i}
        for i, s in enumerate(["a", "a", "a", "b"])
    ]

    hubs = detector.detect_fan_out_hubs(transactions, threshold_outgoing=3)
    assert len(hubs) == 1
    assert hubs[0]["account"] == "a"
    assert hubs[0]["outgoing_transfer_count"] == 3

    hubs = detector.detect_fan_out_hubs(transactions, threshold_outgoing=4)
def test_detect_fan_in_hubs_respects_threshold():
    """Fan-in detection correctly filters below threshold."""
    detector = FraudPatternDetector()
    transactions = [
        {"source_account": "s1", "target_account": t, "amount": 100, "timestamp": i}
        for i, t in enumerate(["a", "a", "a", "b"])
    ]

    hubs = detector.detect_fan_in_hubs(transactions, threshold_incoming=3)
    assert len(hubs) == 1
    assert hubs[0]["account"] == "a"
    assert hubs[0]["incoming_transfer_count"] == 3

    hubs = detector.detect_fan_in_hubs(transactions, threshold_incoming=4)
    assert len(hubs) == 0


def test_detect_mule_rings_respects_max_cycle_length(monkeypatch):
    detector = FraudPatternDetector(min_chain_length=3)
    transactions = _make_transactions(
        [
            ("A", "B"),
            ("B", "C"),
            ("C", "D"),
            ("D", "A"),
        ]
    )

    monkeypatch.setattr(
        "src.features.fraud_pattern_detector.nx.simple_cycles",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("simple_cycles should not be called")),
    )

    rings = detector.detect_mule_rings(
        transactions,
        reference_time=datetime.now(timezone.utc),
        max_cycle_length=3,
        max_cycle_count=10,
    )

    assert rings == []


def test_detect_mule_rings_stops_after_cycle_limit(monkeypatch):
    detector = FraudPatternDetector(min_chain_length=3)
    transactions = _make_transactions(
        [
            ("A", "B"),
            ("B", "C"),
            ("C", "A"),
            ("D", "E"),
            ("E", "F"),
            ("F", "D"),
            ("G", "H"),
            ("H", "I"),
            ("I", "G"),
        ]
    )

    monkeypatch.setattr(
        "src.features.fraud_pattern_detector.nx.simple_cycles",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("simple_cycles should not be called")),
    )

    rings = detector.detect_mule_rings(
        transactions,
        reference_time=datetime.now(timezone.utc),
        max_cycle_length=3,
        max_cycle_count=2,
    )

    assert len(rings) == 2
    assert all(ring["chain_length"] == 3 for ring in rings)
