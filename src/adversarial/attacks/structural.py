"""
Structural attacks: perturb graph topology.

Implemented:
    - EdgeAddition: append random edges to the graph
"""
from __future__ import annotations
import math
import torch
from ..base import BaseAttack, Graph


class EdgeAddition(BaseAttack):
    """Append random edges to the graph.

    Budget = fraction of existing edges to add as new edges.
    Budget 0.05 on a graph with 60 edges adds 3 new edges (rounded up, min 1).
    New edges sample random endpoints, edge_type, and edge_timestamp from the
    same ranges used in training data.
    """
    name = "edge_addition"

    def perturb(self, graph: Graph) -> Graph:
        num_nodes = graph["x"].shape[0]
        num_edges = graph["edge_index"].shape[1]
        n_new = max(1, math.ceil(num_edges * self.config.budget))
        num_edge_types = int(graph["edge_type"].max().item()) + 1 if num_edges > 0 else 4

        gen = torch.Generator().manual_seed(self.config.seed)
        new_ei = torch.randint(0, num_nodes, (2, n_new), generator=gen)
        new_et = torch.randint(0, num_edge_types, (n_new,), generator=gen)
        new_ts = torch.rand(n_new, generator=gen) * 86400

        return {
            **graph,
            "edge_index": torch.cat([graph["edge_index"], new_ei], dim=1),
            "edge_type": torch.cat([graph["edge_type"], new_et], dim=0),
            "edge_timestamp": torch.cat([graph["edge_timestamp"], new_ts], dim=0),
        }
        
class EdgeDeletion(BaseAttack):
    """Remove random edges from the graph.

    Budget = fraction of edges to remove. Budget 0.05 on a graph with 60 edges
    removes 3 edges. Always keeps at least 1 edge so the graph stays non-empty.
    """
    name = "edge_deletion"

    def perturb(self, graph: Graph) -> Graph:
        num_edges = graph["edge_index"].shape[1]
        if num_edges <= 1:
            return {**graph}

        n_remove = max(1, math.ceil(num_edges * self.config.budget))
        n_remove = min(n_remove, num_edges - 1)

        gen = torch.Generator().manual_seed(self.config.seed)
        perm = torch.randperm(num_edges, generator=gen)
        keep = torch.ones(num_edges, dtype=torch.bool)
        keep[perm[:n_remove]] = False

        return {
            **graph,
            "edge_index": graph["edge_index"][:, keep],
            "edge_type": graph["edge_type"][keep],
            "edge_timestamp": graph["edge_timestamp"][keep],
        }
        
class NodeInjection(BaseAttack):
    """Inject benign-looking nodes connected to existing nodes.

    Budget = fraction of existing nodes to add. Budget 0.05 on a 30-node graph
    adds 1 new node (rounded up, minimum 1). Each new node gets:
        - Feature vector sampled from N(0, 1)
        - Random node_type (within existing range)
        - `edges_per_new_node` edges connecting it to random existing nodes

    Simulates an adversary creating fake accounts that link into a mule ring
    to dilute its detection signal.
    """
    name = "node_injection"
    edges_per_new_node: int = 2

    def perturb(self, graph: Graph) -> Graph:
        num_nodes = graph["x"].shape[0]
        feature_dim = graph["x"].shape[1]
        num_node_types = int(graph["node_type"].max().item()) + 1
        num_edge_types = (
            int(graph["edge_type"].max().item()) + 1
            if graph["edge_index"].shape[1] > 0 else 4
        )

        n_new_nodes = max(1, math.ceil(num_nodes * self.config.budget))
        n_new_edges = n_new_nodes * self.edges_per_new_node

        gen = torch.Generator().manual_seed(self.config.seed)

        new_x = torch.randn(n_new_nodes, feature_dim, generator=gen)
        new_node_type = torch.randint(0, num_node_types, (n_new_nodes,), generator=gen)

        new_node_ids = torch.arange(num_nodes, num_nodes + n_new_nodes)
        sources = new_node_ids.repeat_interleave(self.edges_per_new_node)
        targets = torch.randint(0, num_nodes, (n_new_edges,), generator=gen)
        new_edge_index = torch.stack([sources, targets])
        new_edge_type = torch.randint(0, num_edge_types, (n_new_edges,), generator=gen)
        new_edge_timestamp = torch.rand(n_new_edges, generator=gen) * 86400

        return {
            "x": torch.cat([graph["x"], new_x], dim=0),
            "edge_index": torch.cat([graph["edge_index"], new_edge_index], dim=1),
            "node_type": torch.cat([graph["node_type"], new_node_type], dim=0),
            "edge_type": torch.cat([graph["edge_type"], new_edge_type], dim=0),
            "edge_timestamp": torch.cat([graph["edge_timestamp"], new_edge_timestamp], dim=0),
        }
        
class DecoyNodeInjection(BaseAttack):
    """Inject decoy nodes targeted specifically at high-degree (high-centrality) nodes.

    Budget = fraction of existing nodes to add as decoy nodes.
    Each new decoy node gets connected to the highest-degree nodes in the graph
    to simulate structural masking/evasion by fraud rings trying to dilute centrality.
    """
    name = "decoy_node_injection"
    edges_per_new_node: int = 2

    def perturb(self, graph: Graph) -> Graph:
        num_nodes = graph["x"].shape[0]
        feature_dim = graph["x"].shape[1]
        num_node_types = int(graph["node_type"].max().item()) + 1
        num_edges = graph["edge_index"].shape[1]
        num_edge_types = (
            int(graph["edge_type"].max().item()) + 1
            if num_edges > 0 else 4
        )

        n_new_nodes = max(1, math.ceil(num_nodes * self.config.budget))
        n_new_edges = n_new_nodes * self.edges_per_new_node

        # Compute degrees of nodes in the graph
        degrees = torch.zeros(num_nodes, dtype=torch.float)
        if num_edges > 0:
            degrees.scatter_add_(0, graph["edge_index"][0], torch.ones(num_edges))
            degrees.scatter_add_(0, graph["edge_index"][1], torch.ones(num_edges))

        # Select target nodes with highest degrees
        _, top_nodes = torch.sort(degrees, descending=True)

        gen = torch.Generator().manual_seed(self.config.seed)

        new_x = torch.randn(n_new_nodes, feature_dim, generator=gen)
        new_node_type = torch.randint(0, num_node_types, (n_new_nodes,), generator=gen)

        new_node_ids = torch.arange(num_nodes, num_nodes + n_new_nodes)
        sources = new_node_ids.repeat_interleave(self.edges_per_new_node)
        
        # Connect to top 30% of highest degree nodes
        k_targets = max(self.edges_per_new_node, math.ceil(num_nodes * 0.3))
        targets_pool = top_nodes[:k_targets]
        
        target_indices = torch.randint(0, len(targets_pool), (n_new_edges,), generator=gen)
        targets = targets_pool[target_indices]

        new_edge_index = torch.stack([sources, targets])
        new_edge_type = torch.randint(0, num_edge_types, (n_new_edges,), generator=gen)
        new_edge_timestamp = torch.rand(n_new_edges, generator=gen) * 86400

        return {
            "x": torch.cat([graph["x"], new_x], dim=0),
            "edge_index": torch.cat([graph["edge_index"], new_edge_index], dim=1),
            "node_type": torch.cat([graph["node_type"], new_node_type], dim=0),
            "edge_type": torch.cat([graph["edge_type"], new_edge_type], dim=0),
            "edge_timestamp": torch.cat([graph["edge_timestamp"], new_edge_timestamp], dim=0),
        }