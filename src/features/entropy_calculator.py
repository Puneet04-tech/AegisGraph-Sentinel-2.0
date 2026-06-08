#
"""
Graph Entropy Calculator

Computes entropy-based anomaly scores for mule account detection

Key concept:
- Legitimate accounts: Connect to similar entities (low entropy)
- Mule accounts: Connect to diverse, random entities (high entropy)
"""
# Working on entropy-based anomaly detection

import logging
logger = logging.getLogger(__name__)
import numpy as np
import networkx as nx
from typing import Dict, List, Optional, Set
from collections import Counter
import math


class GraphEntropyCalculator:
    """
    Calculate graph entropy metrics for fraud detection
    
    Methods:
    1. Neighbor Feature Entropy: Diversity of neighbor attributes
    2. Structural Entropy: Randomness in network structure
    3. Temporal Entropy: Irregularity in timing patterns
    
    Args:
        neighborhood_size: k-hop neighborhood size
    """
    
    def __init__(self, neighborhood_size: int = 2):
        self.neighborhood_size = neighborhood_size

    def calculate_neighbor_entropy(self, graph: nx.Graph, node: str) -> float:
        """Compatibility wrapper used by tests and legacy code."""
        if graph is None or not graph.has_node(node):
            return 0.0

        if graph.is_directed():
            in_count = len(set(graph.predecessors(node)))
            out_count = len(set(graph.successors(node)))
            counts = [count for count in (in_count, out_count) if count > 0]
            if len(counts) < 2:
                return float(np.log2(sum(counts) + 1)) if counts else 0.0
            total = float(sum(counts))
            probs = [count / total for count in counts]
            return float(-sum(p * math.log2(p) if p > 0 else 0 for p in probs))
        else:
            neighbors = set(graph.neighbors(node))

            if not neighbors:
                return 0.0

            neighbor_degrees = [graph.degree(neighbor) for neighbor in neighbors]

            if len(neighbor_degrees) < 2:
                return 0.0

            bins = [0, 1, 5, 10, 50, 100, float('inf')]
            binned_degrees = np.digitize(neighbor_degrees, bins)
            counts = Counter(binned_degrees)
            total = len(neighbor_degrees)
            probs = [count / total for count in counts.values()]
            return float(-sum(p * math.log2(p) if p > 0 else 0 for p in probs))
    
    def compute_neighbor_entropy(
        self,
        node: str,
        graph: nx.Graph,
        node_attributes: Dict[str, Dict],
        attribute_key: str = 'type',
        neighborhood_profile: Optional[Dict[str, object]] = None,
    ) -> float:
        """
        Compute entropy based on diversity of neighbor attributes
        
        H(v) = -Σ p(f) log p(f)
        
        High entropy → neighbors are diverse → suspicious
        Low entropy → neighbors are similar → legitimate
        
        Args:
            node: Target node
            graph: Graph structure
            node_attributes: Dictionary mapping node to attributes
            attribute_key: Which attribute to compute entropy over
        
        Returns:
            Entropy value
        """
        try:
            profile = neighborhood_profile or self._build_neighborhood_profile(
                node,
                graph,
            )
            neighbors = profile["k_hop_neighbors"]
            
            if len(neighbors) == 0:
                return 0.0
            
            # Collect attribute values
            attribute_values = []
            for neighbor in neighbors:
                if neighbor in node_attributes:
                    attr = node_attributes[neighbor].get(attribute_key, 'unknown')
                    attribute_values.append(attr)
            
            if not attribute_values:
                return 0.0
            
            # Compute probability distribution
            counts = Counter(attribute_values)
            total = len(attribute_values)
            probs = [count / total for count in counts.values()]
            
            # Compute entropy
            entropy = -sum(p * math.log2(p) if p > 0 else 0 for p in probs)
            
            return entropy
        
        except nx.NetworkXError:
            return 0.0
    
    def compute_degree_entropy(
        self,
        node: str,
        graph: nx.Graph,
        neighborhood_profile: Optional[Dict[str, object]] = None,
    ) -> Dict[str, float]:
        """
        Compute entropy based on degree distribution of neighbors
        
        Args:
            node: Target node
            graph: Graph structure
        
        Returns:
            Dictionary with entropy metrics
        """
        try:
            profile = neighborhood_profile or self._build_neighborhood_profile(
                node,
                graph,
            )
            neighbors = list(profile["direct_neighbors"])
            
            if len(neighbors) == 0:
                return {"degree_entropy": 0.0}
            
            # Compute probability distribution
            degrees = list(profile.get("neighbor_degrees") or [])
            if not degrees:
                degrees = [graph.degree(neighbor) for neighbor in neighbors]
            bins = [0, 1, 5, 10, 50, 100, float('inf')]
            binned_degrees = np.digitize(degrees, bins)
            counts = Counter(binned_degrees)
            total = len(degrees)
            probs = [count / total for count in counts.values()]
            
            # Compute entropy
            entropy = -sum(p * math.log2(p) if p > 0 else 0 for p in probs)
            
            return {"degree_entropy": entropy}
        
        except nx.NetworkXError:
            return {"degree_entropy": 0.0}

    def _get_k_hop_neighbors(self, node: str, graph: nx.Graph, k: Optional[int] = None) -> Set[str]:
        if graph is None or not graph.has_node(node):
            return set()

        max_depth = self.neighborhood_size if k is None else k
        visited = {node}
        frontier = {node}
        neighbors: Set[str] = set()

        for _ in range(max_depth):
            next_frontier = set()
            for current in frontier:
                current_neighbors = set(graph.neighbors(current))
                next_frontier.update(current_neighbors - visited)
            if not next_frontier:
                break
            neighbors.update(next_frontier)
            visited.update(next_frontier)
            frontier = next_frontier

        return neighbors

    def _count_edges_between_neighbors(self, graph: nx.Graph, neighbors: Set[str]) -> int:
        if not neighbors:
            return 0
        subgraph = graph.subgraph(neighbors)
        return subgraph.number_of_edges()

    def _build_neighborhood_profile(self, node: str, graph: nx.Graph) -> Dict[str, object]:
        direct_neighbors = set(graph.neighbors(node)) if graph is not None and graph.has_node(node) else set()
        k_hop_neighbors = self._get_k_hop_neighbors(node, graph)
        subgraph_nodes = set(k_hop_neighbors)
        subgraph_nodes.add(node)
        subgraph = graph.subgraph(subgraph_nodes) if graph is not None else None

        return {
            "direct_neighbors": direct_neighbors,
            "k_hop_neighbors": k_hop_neighbors,
            "subgraph": subgraph,
            "neighbor_degrees": [graph.degree(neighbor) for neighbor in direct_neighbors] if graph is not None else [],
            "edges_between_neighbors": self._count_edges_between_neighbors(graph, direct_neighbors) if graph is not None else 0,
        }

    def compute_structural_entropy(
        self,
        node: str,
        graph: nx.Graph,
        neighborhood_profile: Optional[Dict[str, object]] = None,
    ) -> Dict[str, float]:
        try:
            profile = neighborhood_profile or self._build_neighborhood_profile(node, graph)
            direct_neighbors = set(profile["direct_neighbors"])
            if len(direct_neighbors) < 2:
                return {"structural_entropy": 0.0, "clustering_coefficient": 0.0}

            possible_edges = len(direct_neighbors) * (len(direct_neighbors) - 1) / 2
            edges_between = float(profile["edges_between_neighbors"])
            clustering = edges_between / possible_edges if possible_edges else 0.0
            structural_entropy = -math.log2(clustering) if clustering > 0 else 0.0
            return {
                "structural_entropy": float(structural_entropy),
                "clustering_coefficient": float(clustering),
            }
        except nx.NetworkXError:
            return {"structural_entropy": 0.0, "clustering_coefficient": 0.0}

    def compute_temporal_entropy(
        self,
        edge_timestamps: Dict,
        current_time: Optional[float] = None,
    ) -> Dict[str, float]:
        if not edge_timestamps:
            return {"temporal_entropy": 0.0}

        timestamps = list(edge_timestamps.values())
        if len(timestamps) < 2:
            return {"temporal_entropy": 0.0}

        intervals = np.diff(sorted(float(timestamp) for timestamp in timestamps))
        if len(intervals) == 0:
            return {"temporal_entropy": 0.0}

        std = float(np.std(intervals))
        mean = float(np.mean(intervals)) or 1.0
        return {"temporal_entropy": min(std / mean, 1.0)}

    def compute_amount_entropy(self, edge_amounts: Dict) -> Dict[str, float]:
        if not edge_amounts:
            return {"amount_entropy": 0.0}

        amounts = [float(amount) for amount in edge_amounts.values()]
        if len(amounts) < 2:
            return {"amount_entropy": 0.0}

        bins = np.histogram_bin_edges(amounts, bins="auto")
        counts, _ = np.histogram(amounts, bins=bins)
        total = counts.sum()
        probs = [count / total for count in counts if count > 0]
        entropy = -sum(p * math.log2(p) for p in probs)
        return {"amount_entropy": float(entropy)}

    def compute_all_entropy_features(
        self,
        node: str,
        graph: nx.Graph,
        node_attributes: Optional[Dict[str, Dict]] = None,
        edge_timestamps: Optional[Dict] = None,
        edge_amounts: Optional[Dict] = None,
        current_time: Optional[float] = None,
    ) -> Dict[str, float]:
        profile = self._build_neighborhood_profile(node, graph)
        features = self.compute_degree_entropy(node, graph, profile)
        features.update(self.compute_structural_entropy(node, graph, profile))
        features["neighbor_entropy"] = self.compute_neighbor_entropy(
            node,
            graph,
            node_attributes or {},
            neighborhood_profile=profile,
        )
        features.update(self.compute_temporal_entropy(edge_timestamps or {}, current_time))
        features.update(self.compute_amount_entropy(edge_amounts or {}))
        return features


def compute_entropy_risk_score(
    node: str,
    graph: nx.Graph,
    node_attributes: Optional[Dict[str, Dict]] = None,
    edge_timestamps: Optional[Dict] = None,
    edge_amounts: Optional[Dict] = None,
    current_time: Optional[float] = None,
) -> float:
    calculator = GraphEntropyCalculator()
    features = calculator.compute_all_entropy_features(
        node,
        graph,
        node_attributes=node_attributes or {},
        edge_timestamps=edge_timestamps or {},
        edge_amounts=edge_amounts or {},
        current_time=current_time,
    )
    normalized = [
        min(features.get("degree_entropy", 0.0) / 3.0, 1.0),
        min(features.get("structural_entropy", 0.0) / 3.0, 1.0),
        min(features.get("neighbor_entropy", 0.0) / 3.0, 1.0),
        min(features.get("temporal_entropy", 0.0), 1.0),
        min(features.get("amount_entropy", 0.0) / 3.0, 1.0),
    ]
    return float(min(sum(normalized) / len(normalized), 1.0))
