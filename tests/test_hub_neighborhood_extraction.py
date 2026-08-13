"""
Unit tests for high-degree hub neighborhood degree capping (Issue #3460).
"""

import time
import networkx as nx
import pytest

from src.inference.risk_scorer import extract_degree_capped_k_hop_subgraph


def test_degree_capped_neighborhood_extraction():
    # Build synthetic high-degree hub merchant account with 1,000 spokes
    g = nx.DiGraph()
    hub_id = "MERCHANT_HUB_001"
    g.add_node(hub_id)

    for i in range(1000):
        customer = f"CUST_{i}"
        g.add_edge(customer, hub_id, timestamp=float(i))

    start = time.time()
    subgraph = extract_degree_capped_k_hop_subgraph(
        graph=g,
        seed_nodes=[hub_id],
        k_hops=2,
        max_neighbors_per_node=50,
    )
    duration_ms = (time.time() - start) * 1000

    # Ensure node extraction was capped
    assert subgraph.number_of_nodes() <= 52  # hub + 50 capped neighbors
    assert duration_ms < 50.0  # Fast execution < 50ms


def test_empty_graph_neighborhood_extraction():
    subgraph = extract_degree_capped_k_hop_subgraph(
        graph=None,
        seed_nodes=["ACC_NONE"],
    )
    assert subgraph.number_of_nodes() == 0
