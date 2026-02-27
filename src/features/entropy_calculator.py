"""
Graph Entropy Calculator

Computes entropy-based anomaly scores for mule account detection

Key concept:
- Legitimate accounts: Connect to similar entities (low entropy)
- Mule accounts: Connect to diverse, random entities (high entropy)
"""

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
    
    def compute_neighbor_entropy(
        self,
        node: str,
        graph: nx.Graph,
        node_attributes: Dict[str, Dict],
        attribute_key: str = 'type',
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
            # Get k-hop neighbors
            neighbors = self._get_k_hop_neighbors(node, graph, self.neighborhood_size)
            
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
            neighbors = list(graph.neighbors(node))
            
            if len(neighbors) == 0:
                return {
                    'degree_entropy': 0.0,
                    'avg_neighbor_degree': 0.0,
                    'degree_variance': 0.0,
                }
            
            # Get neighbor degrees
            neighbor_degrees = [graph.degree(n) for n in neighbors]
            
            # Binning degrees for entropy calculation
            bins = [0, 1, 5, 10, 50, 100, float('inf')]
            binned_degrees = np.digitize(neighbor_degrees, bins)
            
            # Compute entropy
            counts = Counter(binned_degrees)
            total = len(neighbor_degrees)
            probs = [count / total for count in counts.values()]
            entropy = -sum(p * math.log2(p) if p > 0 else 0 for p in probs)
            
            return {
                'degree_entropy': entropy,
                'avg_neighbor_degree': np.mean(neighbor_degrees),
                'degree_variance': np.var(neighbor_degrees),
            }
        
        except nx.NetworkXError:
            return {
                'degree_entropy': 0.0,
                'avg_neighbor_degree': 0.0,
                'degree_variance': 0.0,
            }
    
    def compute_temporal_entropy(
        self,
        node: str,
        edge_timestamps: Dict[tuple, float],
        current_time: float,
        time_window: float = 86400.0,  # 24 hours
    ) -> float:
        """
        Compute entropy of transaction timing patterns
        
        Regular patterns → low entropy → legitimate
        Irregular patterns → high entropy → suspicious
        
        Args:
            node: Target node
            edge_timestamps: Dictionary mapping (src, tgt) → timestamp
            current_time: Current timestamp
            time_window: Time window to consider
        
        Returns:
            Temporal entropy
        """
        # Collect timestamps for node's edges
        timestamps = []
        for (src, tgt), ts in edge_timestamps.items():
            if (src == node or tgt == node) and (current_time - ts) <= time_window:
                timestamps.append(ts)
        
        if len(timestamps) < 2:
            return 0.0
        
        # Compute time differences
        timestamps = sorted(timestamps)
        time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        # Bin time differences (seconds)
        bins = [0, 60, 300, 3600, 86400, float('inf')]  # 1min, 5min, 1hr, 1day
        binned_diffs = np.digitize(time_diffs, bins)
        
        # Compute entropy
        counts = Counter(binned_diffs)
        total = len(time_diffs)
        probs = [count / total for count in counts.values()]
        entropy = -sum(p * math.log2(p) if p > 0 else 0 for p in probs)
        
        return entropy
    
    def compute_structural_entropy(
        self,
        node: str,
        graph: nx.Graph,
    ) -> Dict[str, float]:
        """
        Compute structural entropy metrics
        
        Measures randomness in local network structure
        
        Args:
            node: Target node
            graph: Graph structure
        
        Returns:
            Dictionary with structural entropy metrics
        """
        try:
            neighbors = set(graph.neighbors(node))
            
            if len(neighbors) < 2:
                return {
                    'clustering_coefficient': 0.0,
                    'local_efficiency': 0.0,
                    'structural_entropy': 0.0,
                }
            
            # Clustering coefficient (how connected are neighbors)
            clustering = nx.clustering(graph, node)
            
            # Local efficiency
            subgraph = graph.subgraph([node] + list(neighbors))
            try:
                local_eff = nx.local_efficiency(subgraph)
            except:
                local_eff = 0.0
            
            # Structural entropy based on edge distribution
            # Count edges between neighbors
            edges_between_neighbors = 0
            for n1 in neighbors:
                for n2 in neighbors:
                    if n1 != n2 and graph.has_edge(n1, n2):
                        edges_between_neighbors += 1
            edges_between_neighbors //= 2  # Undirected graph
            
            # Maximum possible edges
            max_edges = len(neighbors) * (len(neighbors) - 1) // 2
            
            if max_edges > 0:
                edge_prob = edges_between_neighbors / max_edges
                # Entropy of random graph with same edge probability
                if 0 < edge_prob < 1:
                    structural_entropy = -(edge_prob * math.log2(edge_prob) + 
                                         (1-edge_prob) * math.log2(1-edge_prob))
                else:
                    structural_entropy = 0.0
            else:
                structural_entropy = 0.0
            
            return {
                'clustering_coefficient': clustering,
                'local_efficiency': local_eff,
                'structural_entropy': structural_entropy,
            }
        
        except nx.NetworkXError:
            return {
                'clustering_coefficient': 0.0,
                'local_efficiency': 0.0,
                'structural_entropy': 0.0,
            }
    
    def compute_transaction_amount_entropy(
        self,
        node: str,
        edge_amounts: Dict[tuple, float],
    ) -> float:
        """
        Compute entropy of transaction amounts
        
        Regular amounts → low entropy → legitimate
        Varied amounts → high entropy → suspicious
        
        Args:
            node: Target node
            edge_amounts: Dictionary mapping (src, tgt) → amount
        
        Returns:
            Amount entropy
        """
        # Collect amounts for node's transactions
        amounts = []
        for (src, tgt), amount in edge_amounts.items():
            if src == node or tgt == node:
                amounts.append(amount)
        
        if len(amounts) < 2:
            return 0.0
        
        # Bin amounts
        bins = [0, 1000, 5000, 10000, 50000, 100000, float('inf')]
        binned_amounts = np.digitize(amounts, bins)
        
        # Compute entropy
        counts = Counter(binned_amounts)
        total = len(amounts)
        probs = [count / total for count in counts.values()]
        entropy = -sum(p * math.log2(p) if p > 0 else 0 for p in probs)
        
        return entropy
    
    def compute_all_entropy_features(
        self,
        node: str,
        graph: nx.Graph,
        node_attributes: Optional[Dict[str, Dict]] = None,
        edge_timestamps: Optional[Dict[tuple, float]] = None,
        edge_amounts: Optional[Dict[tuple, float]] = None,
        current_time: Optional[float] = None,
    ) -> Dict[str, float]:
        """
        Compute all entropy-based features
        
        Args:
            node: Target node
            graph: Graph structure
            node_attributes: Node attributes
            edge_timestamps: Edge timestamps
            edge_amounts: Edge amounts
            current_time: Current time
        
        Returns:
            Dictionary with all entropy features
        """
        features = {}
        
        # Neighbor entropy
        if node_attributes is not None:
            for attr_key in ['type', 'category']:
                if any(attr_key in attrs for attrs in node_attributes.values()):
                    entropy = self.compute_neighbor_entropy(node, graph, node_attributes, attr_key)
                    features[f'neighbor_entropy_{attr_key}'] = entropy
        
        # Degree entropy
        degree_features = self.compute_degree_entropy(node, graph)
        features.update(degree_features)
        
        # Structural entropy
        structural_features = self.compute_structural_entropy(node, graph)
        features.update(structural_features)
        
        # Temporal entropy
        if edge_timestamps is not None and current_time is not None:
            features['temporal_entropy'] = self.compute_temporal_entropy(
                node, edge_timestamps, current_time
            )
        
        # Amount entropy
        if edge_amounts is not None:
            features['amount_entropy'] = self.compute_transaction_amount_entropy(
                node, edge_amounts
            )
        
        return features
    
    def _get_k_hop_neighbors(
        self,
        node: str,
        graph: nx.Graph,
        k: int,
    ) -> Set[str]:
        """Get k-hop neighbors of a node"""
        if k == 0:
            return {node}
        
        neighbors = set()
        current_layer = {node}
        
        for _ in range(k):
            next_layer = set()
            for n in current_layer:
                if graph.has_node(n):
                    next_layer.update(graph.neighbors(n))
            neighbors.update(next_layer)
            current_layer = next_layer
        
        return neighbors


def compute_entropy_risk_score(
    node: str,
    graph: nx.Graph,
    node_attributes: Optional[Dict[str, Dict]] = None,
    edge_timestamps: Optional[Dict[tuple, float]] = None,
    edge_amounts: Optional[Dict[tuple, float]] = None,
    current_time: Optional[float] = None,
) -> float:
    """
    Compute overall entropy-based fraud risk score
    
    Args:
        node: Target node
        graph: Graph structure
        node_attributes: Node attributes
        edge_timestamps: Edge timestamps
        edge_amounts: Edge amounts
        current_time: Current time
    
    Returns:
        Entropy risk score (0-1)
    """
    calculator = GraphEntropyCalculator()
    features = calculator.compute_all_entropy_features(
        node, graph, node_attributes, edge_timestamps, edge_amounts, current_time
    )
    
    # Combine features into risk score
    risk = 0.0
    
    # High neighbor entropy → high risk
    if 'neighbor_entropy_type' in features:
        neighbor_entropy_norm = min(features['neighbor_entropy_type'] / 3.0, 1.0)
        risk += 0.3 * neighbor_entropy_norm
    
    # High degree entropy → high risk
    if 'degree_entropy' in features:
        degree_entropy_norm = min(features['degree_entropy'] / 3.0, 1.0)
        risk += 0.2 * degree_entropy_norm
    
    # Low clustering (random connections) → high risk
    if 'clustering_coefficient' in features:
        clustering_risk = 1.0 - features['clustering_coefficient']
        risk += 0.2 * clustering_risk
    
    # High temporal entropy → high risk
    if 'temporal_entropy' in features:
        temporal_entropy_norm = min(features['temporal_entropy'] / 2.0, 1.0)
        risk += 0.15 * temporal_entropy_norm
    
    # High amount entropy → high risk
    if 'amount_entropy' in features:
        amount_entropy_norm = min(features['amount_entropy'] / 2.0, 1.0)
        risk += 0.15 * amount_entropy_norm
    
    return min(risk, 1.0)
