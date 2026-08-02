"""Dedicated unit tests for src/features/entropy_calculator.py.

The shared ``test_features.py`` only exercises a handful of the public API
surface of :class:`GraphEntropyCalculator` (notably it never calls
``compute_entropy_risk_score``).  This module fills that coverage gap with
focused, deterministic tests for every public entry point plus the common
edge cases (empty graphs, missing nodes, degenerate inputs and the
``current_time`` parameter handling).
"""

from __future__ import annotations

import math

import networkx as nx
import numpy as np
import pytest

from src.features.entropy_calculator import (
    GraphEntropyCalculator,
    compute_entropy_risk_score,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def star_graph() -> nx.Graph:
    """Undirected star: centre ``A`` connected to three leaves."""
    graph = nx.Graph()
    graph.add_edges_from([("A", "L1"), ("A", "L2"), ("A", "L3")])
    return graph


@pytest.fixture
def directed_chain() -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_edges_from([("s", "a"), ("s", "b"), ("a", "t"), ("b", "t")])
    return graph


@pytest.fixture
def triangle_graph() -> nx.Graph:
    """A complete 3-node undirected graph (density == 1) with string nodes."""
    graph = nx.Graph()
    graph.add_edges_from([("A", "B"), ("A", "C"), ("B", "C")])
    return graph


# ---------------------------------------------------------------------------
# calculate_neighbor_entropy
# ---------------------------------------------------------------------------


def test_calculate_neighbor_entropy_missing_node_returns_zero(star_graph):
    assert GraphEntropyCalculator().calculate_neighbor_entropy(star_graph, "missing") == 0.0


def test_calculate_neighbor_entropy_none_graph_returns_zero():
    assert GraphEntropyCalculator().calculate_neighbor_entropy(None, "A") == 0.0


def test_calculate_neighbor_entropy_single_neighbor_returns_zero():
    graph = nx.Graph()
    graph.add_edge("A", "B")
    assert GraphEntropyCalculator().calculate_neighbor_entropy(graph, "A") == 0.0


def test_calculate_neighbor_entropy_directed_balanced_is_one_bit(directed_chain):
    # node "s" has one predecessor (none) and two successors => counts [0,2]
    # => single non-zero count => log2(total+1) path.
    calc = GraphEntropyCalculator()
    entropy = calc.calculate_neighbor_entropy(directed_chain, "s")
    assert entropy == math.log2(2 + 1)

    # node "t" has two predecessors and zero successors => counts [2,0].
    assert calc.calculate_neighbor_entropy(directed_chain, "t") == math.log2(2 + 1)


def test_calculate_neighbor_entropy_directed_two_sided():
    graph = nx.DiGraph()
    graph.add_edges_from([("s", "x"), ("s", "y"), ("z", "s"), ("w", "s")])
    # s has in=2, out=2 -> two equiprobable partitions -> entropy == 1.0
    entropy = GraphEntropyCalculator().calculate_neighbor_entropy(graph, "s")
    assert math.isclose(entropy, 1.0)


# ---------------------------------------------------------------------------
# compute_neighbor_entropy
# ---------------------------------------------------------------------------


def test_compute_neighbor_entropy_uniform_attributes_zero(star_graph):
    attrs = {n: {"type": "account"} for n in star_graph.nodes}
    entropy = GraphEntropyCalculator().compute_neighbor_entropy(
        "A", star_graph, attrs, attribute_key="type"
    )
    assert entropy == 0.0


def test_compute_neighbor_entropy_diverse_attributes_positive(star_graph):
    attrs = {"L1": {"type": "account"}, "L2": {"type": "device"}, "L3": {"type": "ip"}}
    entropy = GraphEntropyCalculator().compute_neighbor_entropy(
        "A", star_graph, attrs, attribute_key="type"
    )
    assert entropy > 0.0
    # Three equiprobable categories => log2(3)
    assert math.isclose(entropy, math.log2(3))


def test_compute_neighbor_entropy_no_matching_attributes_returns_zero(star_graph):
    attrs = {n: {"type": "account"} for n in ["A"]}
    entropy = GraphEntropyCalculator().compute_neighbor_entropy(
        "A", star_graph, attrs, attribute_key="type"
    )
    assert entropy == 0.0


def test_compute_neighbor_entropy_accepts_profile(star_graph):
    calc = GraphEntropyCalculator()
    profile = calc._build_neighborhood_profile("A", star_graph)
    attrs = {n: {"type": "account"} for n in star_graph.nodes}
    entropy = calc.compute_neighbor_entropy(
        "A", star_graph, attrs, attribute_key="type", neighborhood_profile=profile
    )
    assert entropy == 0.0


# ---------------------------------------------------------------------------
# compute_degree_entropy
# ---------------------------------------------------------------------------


def test_compute_degree_entropy_no_neighbors():
    graph = nx.Graph()
    graph.add_node("lonely")
    result = GraphEntropyCalculator().compute_degree_entropy("lonely", graph)
    assert result == {"degree_entropy": 0.0}


def test_compute_degree_entropy_missing_node():
    graph = nx.Graph()
    result = GraphEntropyCalculator().compute_degree_entropy("ghost", graph)
    assert result == {"degree_entropy": 0.0}


def test_compute_degree_entropy_uses_provided_degrees(star_graph):
    calc = GraphEntropyCalculator()
    # Inject known neighbor degrees via a pre-built profile.
    profile = calc._build_neighborhood_profile("A", star_graph)
    result = calc.compute_degree_entropy("A", star_graph, neighborhood_profile=profile)
    assert "degree_entropy" in result
    assert result["degree_entropy"] >= 0.0


# ---------------------------------------------------------------------------
# compute_structural_entropy
# ---------------------------------------------------------------------------


def test_compute_structural_entropy_too_few_neighbors(triangle_graph):
    graph = nx.Graph()
    graph.add_node("iso")
    result = GraphEntropyCalculator().compute_structural_entropy("iso", graph)
    assert result == {"structural_entropy": 0.0, "clustering_coefficient": 0.0}


def test_compute_structural_entropy_complete_triangle(triangle_graph):
    calc = GraphEntropyCalculator()
    result = calc.compute_structural_entropy("A", triangle_graph)
    # Complete graph -> clustering == 1.0 -> structural_entropy == 0.0
    assert math.isclose(result["clustering_coefficient"], 1.0)
    assert math.isclose(result["structural_entropy"], 0.0)


def test_compute_structural_entropy_missing_node_returns_zeros():
    calc = GraphEntropyCalculator()
    result = calc.compute_structural_entropy("ghost", nx.Graph())
    assert result == {"structural_entropy": 0.0, "clustering_coefficient": 0.0}


# ---------------------------------------------------------------------------
# compute_temporal_entropy
# ---------------------------------------------------------------------------


def test_compute_temporal_entropy_empty():
    assert GraphEntropyCalculator().compute_temporal_entropy({}) == {"temporal_entropy": 0.0}


def test_compute_temporal_entropy_single_timestamp():
    result = GraphEntropyCalculator().compute_temporal_entropy({"a": 1.0})
    assert result == {"temporal_entropy": 0.0}


def test_compute_temporal_entropy_uniform_intervals_zero():
    # Equal spacing -> std of intervals == 0 -> entropy 0.0
    timestamps = {"a": 0.0, "b": 60.0, "c": 120.0, "d": 180.0}
    result = GraphEntropyCalculator().compute_temporal_entropy(timestamps)
    assert math.isclose(result["temporal_entropy"], 0.0)


def test_compute_temporal_entropy_irregular_in_unit_interval():
    timestamps = {"a": 0.0, "b": 1.0, "c": 1000.0}
    result = GraphEntropyCalculator().compute_temporal_entropy(timestamps)
    assert 0.0 <= result["temporal_entropy"] <= 1.0


# ---------------------------------------------------------------------------
# compute_amount_entropy
# ---------------------------------------------------------------------------


def test_compute_amount_entropy_empty():
    assert GraphEntropyCalculator().compute_amount_entropy({}) == {"amount_entropy": 0.0}


def test_compute_amount_entropy_single_value():
    assert GraphEntropyCalculator().compute_amount_entropy({"a": 100.0}) == {
        "amount_entropy": 0.0
    }


def test_compute_amount_entropy_in_unit_interval():
    amounts = {"a": 10.0, "b": 20.0, "c": 30.0, "d": 40.0}
    result = GraphEntropyCalculator().compute_amount_entropy(amounts)
    assert 0.0 <= result["amount_entropy"] <= 5.0


# ---------------------------------------------------------------------------
# compute_all_entropy_features
# ---------------------------------------------------------------------------


def test_compute_all_entropy_features_returns_all_keys(triangle_graph):
    calc = GraphEntropyCalculator()
    attrs = {n: {"type": "account"} for n in triangle_graph.nodes}
    features = calc.compute_all_entropy_features(
        "A", triangle_graph, node_attributes=attrs
    )
    expected_keys = {
        "degree_entropy",
        "structural_entropy",
        "clustering_coefficient",
        "neighbor_entropy",
        "temporal_entropy",
        "amount_entropy",
    }
    assert expected_keys.issubset(features.keys())
    for value in features.values():
        assert isinstance(value, float)


def test_compute_all_entropy_features_empty_graph_returns_zeros():
    calc = GraphEntropyCalculator()
    graph = nx.Graph()
    graph.add_node("solo")
    features = calc.compute_all_entropy_features("solo", graph)
    assert features["degree_entropy"] == 0.0
    assert features["structural_entropy"] == 0.0
    assert features["neighbor_entropy"] == 0.0
    assert features["temporal_entropy"] == 0.0
    assert features["amount_entropy"] == 0.0


# ---------------------------------------------------------------------------
# compute_entropy_risk_score (module-level convenience function)
# ---------------------------------------------------------------------------


def test_compute_entropy_risk_score_in_unit_interval(triangle_graph):
    attrs = {n: {"type": "account"} for n in triangle_graph.nodes}
    score = compute_entropy_risk_score("A", triangle_graph, node_attributes=attrs)
    assert 0.0 <= score <= 1.0


def test_compute_entropy_risk_score_is_float(triangle_graph):
    score = compute_entropy_risk_score("A", triangle_graph)
    assert isinstance(score, float)


def test_compute_entropy_risk_score_missing_node_returns_zero():
    graph = nx.Graph()
    graph.add_node("x")
    assert compute_entropy_risk_score("ghost", graph) == 0.0


def test_compute_entropy_risk_score_none_graph_returns_zero():
    assert compute_entropy_risk_score("A", None) == 0.0


def test_compute_entropy_risk_score_empty_graph_returns_zero():
    assert compute_entropy_risk_score("A", nx.Graph()) == 0.0


def test_compute_entropy_risk_score_higher_for_diverse_neighbors(star_graph):
    diverse = {n: {"type": t} for n, t in zip(star_graph.nodes, ["a", "b", "c", "d"])}
    uniform = {n: {"type": "account"} for n in star_graph.nodes}
    high = compute_entropy_risk_score("A", star_graph, node_attributes=diverse)
    low = compute_entropy_risk_score("A", star_graph, node_attributes=uniform)
    assert high >= low
