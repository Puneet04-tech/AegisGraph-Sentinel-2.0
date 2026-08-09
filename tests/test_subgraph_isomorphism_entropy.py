"""
Unit tests for Dynamic Graph Entropy Anomaly Detection via Subgraph Isomorphism (Issue #3455).
"""

import networkx as nx
import pytest

from src.graph_analytics.motif_catalog import get_laundering_motifs, build_circular_ring_motif
from src.features.entropy_calculator import GraphEntropyCalculator


def test_motif_catalog_retrieval():
    motifs = get_laundering_motifs()
    assert "CIRCULAR_RING" in motifs
    assert "SMURFING_HUB" in motifs
    assert "SCATTER_GATHER" in motifs
    assert motifs["CIRCULAR_RING"]["base_risk"] == 0.85


def test_subgraph_isomorphism_matching_circular_ring():
    calculator = GraphEntropyCalculator()
    
    # Construct graph containing a circular ring A -> B -> C -> D -> A
    g = nx.DiGraph()
    edges = [("ACC1", "ACC2"), ("ACC2", "ACC3"), ("ACC3", "ACC4"), ("ACC4", "ACC1")]
    g.add_edges_from(edges)

    matches = calculator.match_laundering_motifs("ACC1", g)
    assert len(matches) > 0
    motif_keys = [m["motif_key"] for m in matches]
    assert "CIRCULAR_RING" in motif_keys


def test_compute_isomorphism_entropy():
    calculator = GraphEntropyCalculator()
    
    # Construct star hub graph
    g = nx.DiGraph()
    edges = [("MULE1", "HUB"), ("MULE2", "HUB"), ("MULE3", "HUB"), ("MULE4", "HUB")]
    g.add_edges_from(edges)

    iso_features = calculator.compute_isomorphism_entropy("HUB", g)
    assert iso_features["isomorphism_entropy"] > 0.0
    assert iso_features["highest_motif_risk"] >= 0.75
