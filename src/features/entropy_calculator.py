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
```