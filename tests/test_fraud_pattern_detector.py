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
