"""
Money Laundering Graph Motif Catalog

Defines topological graph patterns (motifs) representing standard financial crime
laundering structures (Circular Rings, Smurfing Hubs, Layering Chains, Scatter-Gather).
"""

from __future__ import annotations

import networkx as nx
from typing import Dict, List, Any


def build_star_hub_motif(num_spokes: int = 4) -> nx.DiGraph:
    """Builds a Star/Hub motif representing smurfing or fan-in/fan-out aggregation."""
    g = nx.DiGraph()
    g.add_node("hub", role="hub")
    for i in range(num_spokes):
        spoke_id = f"spoke_{i}"
        g.add_node(spoke_id, role="proxy")
        g.add_edge(spoke_id, "hub", edge_type="transfer")
    return g


def build_circular_ring_motif(ring_size: int = 4) -> nx.DiGraph:
    """Builds a Circular Ring motif representing cyclic money layering (A -> B -> C -> A)."""
    g = nx.DiGraph()
    for i in range(ring_size):
        curr_node = f"ring_{i}"
        next_node = f"ring_{(i + 1) % ring_size}"
        g.add_node(curr_node, role="ring_member")
        g.add_edge(curr_node, next_node, edge_type="transfer")
    return g


def build_layering_chain_motif(chain_length: int = 4) -> nx.DiGraph:
    """Builds a Layering Chain motif representing sequential obfuscation transfers."""
    g = nx.DiGraph()
    for i in range(chain_length):
        curr_node = f"chain_{i}"
        g.add_node(curr_node, role="mule_link")
        if i > 0:
            prev_node = f"chain_{i-1}"
            g.add_edge(prev_node, curr_node, edge_type="transfer")
    return g


def build_scatter_gather_motif(num_proxies: int = 3) -> nx.DiGraph:
    """Builds a Scatter-Gather motif (Source -> N Proxies -> Sink)."""
    g = nx.DiGraph()
    g.add_node("source", role="source")
    g.add_node("sink", role="sink")
    for i in range(num_proxies):
        proxy_id = f"proxy_{i}"
        g.add_node(proxy_id, role="proxy")
        g.add_edge("source", proxy_id, edge_type="transfer")
        g.add_edge(proxy_id, "sink", edge_type="transfer")
    return g


def build_syndicate_mesh_motif(mesh_size: int = 4) -> nx.DiGraph:
    """Builds a dense mesh motif representing an interconnected fraud ring."""
    g = nx.complete_graph(mesh_size, create_using=nx.DiGraph)
    for node in g.nodes():
        g.nodes[node]["role"] = "syndicate_member"
    return g


def get_laundering_motifs() -> Dict[str, Dict[str, Any]]:
    """Returns catalog of money laundering motifs with metadata and risk weights.

    Returns:
        Dict mapping motif name to metadata dict containing graph instance and risk score.
    """
    return {
        "CIRCULAR_RING": {
            "name": "Circular Layering Ring",
            "graph": build_circular_ring_motif(ring_size=4),
            "base_risk": 0.85,
            "description": "Cyclic money movement between accounts returning to origin",
        },
        "SMURFING_HUB": {
            "name": "Smurfing / Fan-In Hub",
            "graph": build_star_hub_motif(num_spokes=4),
            "base_risk": 0.80,
            "description": "Aggregation hub receiving multiple micro-deposits",
        },
        "LAYERING_CHAIN": {
            "name": "Deep Layering Chain",
            "graph": build_layering_chain_motif(chain_length=4),
            "base_risk": 0.75,
            "description": "Multi-hop rapid transfer chain obfuscating source of funds",
        },
        "SCATTER_GATHER": {
            "name": "Scatter-Gather Network",
            "graph": build_scatter_gather_motif(num_proxies=3),
            "base_risk": 0.90,
            "description": "Fan-out to proxies followed by consolidation into single sink",
        },
        "SYNDICATE_MESH": {
            "name": "Fraud Syndicate Mesh",
            "graph": build_syndicate_mesh_motif(mesh_size=4),
            "base_risk": 0.95,
            "description": "Fully connected cross-account transfer mesh",
        },
    }
