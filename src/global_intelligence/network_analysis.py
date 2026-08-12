"""
Network Analysis Engine for fraud network discovery and analysis.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid
import math

from .models import (
    FraudNetwork,
    NetworkType,
    ThreatLevel,
    FederatedEntity,
    EntityType,
)
from src.graph_analytics.centrality import all_centralities, graph_diameter

from .store import GlobalIntelligenceStore, get_global_intelligence_store
from .knowledge_graph import KnowledgeGraphEngine, get_knowledge_graph_engine


@dataclass
class CommunityDetection:
    """Result of community detection."""
    community_id: str
    member_ids: List[str]
    community_type: str
    metrics: Dict[str, float]
    discovered_at: datetime


@dataclass
class CentralityMetrics:
    """Centrality metrics for network nodes."""
    node_id: str
    degree_centrality: float
    betweenness_centrality: float
    closeness_centrality: float
    eigenvector_centrality: float
    pagerank: float


@dataclass
class NetworkAnalysisConfig:
    """Configuration for network analysis."""
    min_community_size: int = 3
    max_community_size: int = 100
    centrality_sample_size: int = 1000
    pagerank_iterations: int = 20


class NetworkAnalysisEngine:
    """
    Analyzes fraud networks and performs graph-based analysis.

    Handles:
    - Network discovery
    - Community detection
    - Centrality analysis
    - Graph metrics calculation
    """

    def __init__(
        self,
        store: Optional[GlobalIntelligenceStore] = None,
        graph_engine: Optional[KnowledgeGraphEngine] = None,
        config: Optional[NetworkAnalysisConfig] = None,
    ):
        self._store = store or get_global_intelligence_store()
        self._graph = graph_engine or get_knowledge_graph_engine()
        self._config = config or NetworkAnalysisConfig()
        # Whole-graph centrality results, memoised until the graph changes size
        # or shape, so ranking many nodes does not repeat the global work.
        self._centrality_cache: Optional[Dict[str, Dict[str, float]]] = None
        self._centrality_cache_key: Optional[Tuple[int, int, Optional[int]]] = None

    def discover_networks(
        self,
        seed_entity_id: Optional[str] = None,
        network_type: Optional[NetworkType] = None,
    ) -> List[FraudNetwork]:
        """Discover fraud networks."""
        networks = []

        if seed_entity_id:
            # Discover from seed entity
            entities = self._discover_connected_entities(seed_entity_id)
            if entities:
                network = self._create_network(entities, network_type)
                if network:
                    networks.append(network)
                    self._store.store_network(network)
        else:
            # Discover all networks
            entities_by_type = self._group_entities_by_connectivity()
            for group_entities in entities_by_type.values():
                if len(group_entities) >= self._config.min_community_size:
                    network = self._create_network(group_entities, network_type)
                    if network:
                        networks.append(network)
                        self._store.store_network(network)

        return networks

    def analyze_network(
        self,
        network_id: str,
    ) -> Dict[str, Any]:
        """Perform comprehensive network analysis."""
        network = self._store.get_network(network_id)
        if not network:
            return {"error": "Network not found"}

        # Calculate various metrics
        metrics = {
            "node_count": len(network.nodes),
            "edge_count": len(network.edges),
            "density": self._calculate_density(network),
            "avg_clustering": self._calculate_avg_clustering(network),
            "diameter": self._estimate_diameter(network),
            "threat_level": network.threat_level.value,
            "activity_score": network.activity_score,
        }

        # Calculate centrality for key nodes
        central_nodes = self._calculate_top_centrality(network, limit=10)

        # Detect subcommunities
        communities = self._detect_subcommunities(network)

        return {
            "network_id": network_id,
            "metrics": metrics,
            "central_nodes": central_nodes,
            "communities": communities,
            "analyzed_at": datetime.now(timezone.utc),
        }

    def detect_communities(
        self,
        network_id: Optional[str] = None,
    ) -> List[CommunityDetection]:
        """Detect communities within networks."""
        if network_id:
            network = self._store.get_network(network_id)
            if not network:
                return []
            node_ids = network.nodes
        else:
            node_ids = list(self._store._graph_nodes.keys())

        communities = []

        # Simple label propagation community detection
        labels = {node: node for node in node_ids}
        changed = True
        iterations = 0

        while changed and iterations < 20:
            changed = False
            iterations += 1

            for node_id in node_ids:
                neighbors = self._get_neighbors(node_id)
                if not neighbors:
                    continue

                neighbor_labels = [labels[n] for n in neighbors]
                most_common = max(set(neighbor_labels), key=neighbor_labels.count)

                if most_common != labels[node_id]:
                    labels[node_id] = most_common
                    changed = True

        # Group nodes by label
        community_groups: Dict[str, List[str]] = defaultdict(list)
        for node_id, label in labels.items():
            community_groups[label].append(node_id)

        # Create community detections
        for community_id, member_ids in community_groups.items():
            if len(member_ids) >= self._config.min_community_size:
                metrics = self._calculate_community_metrics(member_ids)
                community = CommunityDetection(
                    community_id=str(uuid.uuid4()),
                    member_ids=member_ids,
                    community_type=self._classify_community(metrics["avg_risk"]),
                    metrics=metrics,
                    discovered_at=datetime.now(timezone.utc),
                )
                communities.append(community)

        return communities

    def calculate_centrality(
        self,
        node_id: str,
    ) -> CentralityMetrics:
        """Calculate centrality metrics for a node."""
        # Get neighbors
        neighbors = self._get_neighbors(node_id)
        all_nodes = list(self._store._graph_nodes.keys())
        n = len(all_nodes)

        # Degree centrality
        degree = len(neighbors) / (n - 1) if n > 1 else 0

        # Simplified centrality calculations
        betweenness = self._calculate_betweenness(node_id, sample_size=100)
        closeness = self._calculate_closeness(node_id)
        eigenvector = self._calculate_eigenvector(node_id)
        pagerank = self._calculate_pagerank(node_id)

        return CentralityMetrics(
            node_id=node_id,
            degree_centrality=degree,
            betweenness_centrality=betweenness,
            closeness_centrality=closeness,
            eigenvector_centrality=eigenvector,
            pagerank=pagerank,
        )

    def identify_key_players(
        self,
        network_id: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Identify key players in the network."""
        if network_id:
            network = self._store.get_network(network_id)
            node_ids = network.nodes if network else []
        else:
            node_ids = list(self._store._graph_nodes.keys())

        player_scores = []

        for node_id in node_ids:
            metrics = self.calculate_centrality(node_id)
            node = self._store.get_graph_node(node_id)

            # Calculate composite score
            composite_score = (
                metrics.degree_centrality * 0.3
                + metrics.betweenness_centrality * 0.3
                + metrics.pagerank * 0.2
                + (node.risk_score if node else 0) * 0.2
            )

            player_scores.append({
                "node_id": node_id,
                "composite_score": composite_score,
                "degree": metrics.degree_centrality,
                "betweenness": metrics.betweenness_centrality,
                "pagerank": metrics.pagerank,
                "risk_score": node.risk_score if node else 0,
                "entity_type": node.entity_type.value if node else "unknown",
            })

        # Sort by composite score
        player_scores.sort(key=lambda x: x["composite_score"], reverse=True)

        return player_scores[:limit]

    def _discover_connected_entities(
        self,
        seed_id: str,
    ) -> List[FederatedEntity]:
        """Discover entities connected to a seed entity."""
        visited: Set[str] = {seed_id}
        entities = []

        # Get seed entity
        seed = self._store.get_entity(seed_id)
        if seed:
            entities.append(seed)

        # BFS to find connected entities
        queue = [seed_id]
        max_depth = 3

        while queue and len(visited) < 100:
            current = queue.pop(0)

            # Find connected nodes in graph
            edges = self._store.get_node_edges(current)
            for edge in edges:
                target = edge.target_id if edge.source_id == current else edge.source_id
                if target not in visited:
                    visited.add(target)
                    entity = self._store.get_entity(target)
                    if entity:
                        entities.append(entity)
                    queue.append(target)

        return entities

    def _group_entities_by_connectivity(self) -> Dict[str, List[FederatedEntity]]:
        """Group entities by their connectivity."""
        components = self._graph.find_connected_components()
        groups: Dict[str, List[FederatedEntity]] = {}

        for i, component in enumerate(components):
            if len(component) >= self._config.min_community_size:
                entities = []
                for entity_id in component:
                    entity = self._store.get_entity(entity_id)
                    if entity:
                        entities.append(entity)
                if entities:
                    groups[f"group_{i}"] = entities

        return groups

    def _create_network(
        self,
        entities: List[FederatedEntity],
        network_type: Optional[NetworkType] = None,
    ) -> Optional[FraudNetwork]:
        """Create a fraud network from entities."""
        if len(entities) < self._config.min_community_size:
            return None

        # Create edges from graph relationships. Only edges whose BOTH
        # endpoints are network members belong to the network: an edge to a
        # non-member node would inflate the edge count/density and let
        # subcommunity traversal leak outside the membership. Edges are also
        # deduplicated because each endpoint visits the same underlying edge.
        edges = []
        node_ids = [e.entity_id for e in entities]
        member_ids = set(node_ids)
        seen_edges: Set[Tuple[str, str]] = set()

        for entity in entities:
            graph_node = self._store.get_graph_node(entity.entity_id)
            if graph_node:
                for edge in self._store.get_node_edges(graph_node.node_id):
                    if (
                        edge.source_id in member_ids
                        and edge.target_id in member_ids
                        and (edge.source_id, edge.target_id) not in seen_edges
                    ):
                        seen_edges.add((edge.source_id, edge.target_id))
                        edges.append({
                            "source": edge.source_id,
                            "target": edge.target_id,
                            "type": edge.relationship_type,
                            "weight": edge.weight,
                        })

        # Calculate network metrics
        threat_levels = [e.threat_level for e in entities]
        if ThreatLevel.CRITICAL in threat_levels:
            threat_level = ThreatLevel.CRITICAL
        elif ThreatLevel.HIGH in threat_levels:
            threat_level = ThreatLevel.HIGH
        else:
            threat_level = ThreatLevel.MEDIUM

        avg_risk = sum(e.risk_score for e in entities) / len(entities)

        network = FraudNetwork(
            network_id=str(uuid.uuid4()),
            network_type=network_type or NetworkType.FRAUD_RING,
            nodes=node_ids,
            edges=edges,
            confidence_score=min(1.0, len(entities) / 10),
            threat_level=threat_level,
            member_count=len(entities),
            activity_score=avg_risk,
            first_detected=min(e.first_seen for e in entities),
            last_activity=max(e.last_updated for e in entities),
            discovery_method="graph_analysis",
            discovered_by="network_analysis_engine",
        )

        return network

    def _get_neighbors(self, node_id: str) -> List[str]:
        """Get neighboring nodes."""
        neighbors = []
        edges = self._store.get_node_edges(node_id)
        for edge in edges:
            if edge.source_id == node_id:
                neighbors.append(edge.target_id)
            else:
                neighbors.append(edge.source_id)
        return neighbors

    def _calculate_density(self, network: FraudNetwork) -> float:
        """Calculate network density."""
        n = len(network.nodes)
        e = len(network.edges)
        if n < 2:
            return 0.0
        return (2 * e) / (n * (n - 1))

    def _calculate_avg_clustering(self, network: FraudNetwork) -> float:
        """Calculate average clustering coefficient."""
        total_clustering = 0.0
        count = 0

        for node_id in network.nodes[:100]:  # Sample for performance
            neighbors = self._get_neighbors(node_id)
            if len(neighbors) < 2:
                continue

            triangles = 0
            possible = len(neighbors) * (len(neighbors) - 1) / 2

            for i, n1 in enumerate(neighbors):
                for n2 in neighbors[i + 1:]:
                    n1_neighbors = set(self._get_neighbors(n1))
                    if n2 in n1_neighbors:
                        triangles += 1

            if possible > 0:
                total_clustering += triangles / possible
                count += 1

        return total_clustering / count if count > 0 else 0.0

    def _estimate_diameter(self, network: FraudNetwork) -> int:
        """Compute the network diameter.

        This previously returned ``min(5, len(nodes) // 5 + 1)`` -- a function
        of node count alone, capped at 5, that never inspected a single edge.
        Now it is the longest shortest path within the network's own subgraph.
        """
        node_ids = list(network.nodes)
        if len(node_ids) <= 1:
            return 0

        member_ids = set(node_ids)
        adjacency: Dict[str, Set[str]] = {node_id: set() for node_id in node_ids}
        for node_id in node_ids:
            # Restricted to members, so an edge leaving the network cannot
            # inflate the diameter of the network itself.
            adjacency[node_id].update(
                n for n in self._get_neighbors(node_id) if n in member_ids
            )

        return graph_diameter(adjacency, node_ids)

    def _calculate_top_centrality(
        self,
        network: FraudNetwork,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Calculate top nodes by centrality."""
        scores = []

        for node_id in network.nodes:
            metrics = self.calculate_centrality(node_id)
            node = self._store.get_graph_node(node_id)

            scores.append({
                "node_id": node_id,
                "degree": metrics.degree_centrality,
                "pagerank": metrics.pagerank,
                "entity_type": node.entity_type.value if node else "unknown",
            })

        scores.sort(key=lambda x: x["degree"], reverse=True)
        return scores[:limit]

    def _detect_subcommunities(
        self,
        network: FraudNetwork,
    ) -> List[List[str]]:
        """Detect subcommunities within a network."""
        # Use simple connected components within the network
        visited: Set[str] = set()
        communities: List[List[str]] = []

        for node_id in network.nodes:
            if node_id in visited:
                continue

            community = []
            queue = [node_id]

            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue

                visited.add(current)
                community.append(current)

                # Add connected nodes
                for edge in network.edges:
                    if edge.get("source") == current:
                        target = edge.get("target")
                        if target not in visited:
                            queue.append(target)
                    elif edge.get("target") == current:
                        source = edge.get("source")
                        if source not in visited:
                            queue.append(source)

            if community:
                communities.append(community)

        return communities

    def _classify_community(self, avg_risk: float) -> str:
        """Classify the type of community from its members' average risk score.

        Mirrors the same tiering style as ``_calculate_risk_level``-type
        thresholds elsewhere: a community is only called a fraud ring once
        its actual member risk supports that label.
        """
        if avg_risk >= 0.7:
            return "fraud_ring"
        elif avg_risk >= 0.4:
            return "suspicious_cluster"
        return "low_risk_cluster"

    def _calculate_community_metrics(
        self,
        member_ids: List[str],
    ) -> Dict[str, float]:
        """Calculate metrics for a community."""
        total_risk = 0.0
        count = 0

        for member_id in member_ids:
            entity = self._store.get_entity(member_id)
            if entity:
                total_risk += entity.risk_score
                count += 1

        return {
            "member_count": len(member_ids),
            "avg_risk": total_risk / count if count > 0 else 0.0,
        }

    def _build_adjacency(self) -> Tuple[Dict[str, Set[str]], List[str]]:
        """Snapshot the whole graph as an adjacency mapping.

        The centrality algorithms are whole-graph computations, so they need
        the full structure rather than one node's neighbourhood.
        """
        node_ids = list(self._store._graph_nodes.keys())
        adjacency: Dict[str, Set[str]] = {node_id: set() for node_id in node_ids}
        for node_id in node_ids:
            adjacency[node_id].update(self._get_neighbors(node_id))
        return adjacency, node_ids

    def _all_centralities(
        self,
        betweenness_sample_size: Optional[int] = None,
    ) -> Dict[str, Dict[str, float]]:
        """Compute every measure once, memoised against the graph size.

        Scoring many nodes previously recomputed the same global quantities per
        node; the cache is invalidated whenever the node count changes.
        """
        adjacency, node_ids = self._build_adjacency()
        cache_key = (len(node_ids), sum(len(v) for v in adjacency.values()), betweenness_sample_size)
        if self._centrality_cache_key == cache_key and self._centrality_cache is not None:
            return self._centrality_cache

        scored = all_centralities(adjacency, node_ids, betweenness_sample_size)
        self._centrality_cache = scored
        self._centrality_cache_key = cache_key
        return scored

    def _calculate_betweenness(
        self,
        node_id: str,
        sample_size: int = 100,
    ) -> float:
        """Calculate betweenness centrality using Brandes' algorithm.

        This previously returned an incident-edge ratio -- degree centrality
        under a different name -- and ignored ``sample_size`` entirely.
        Betweenness is the measure that surfaces bridging accounts, which a
        degree-based approximation cannot see.
        """
        _, node_ids = self._build_adjacency()
        # Sampling only pays off once the graph is larger than the sample.
        effective = sample_size if sample_size and sample_size < len(node_ids) else None
        return self._all_centralities(effective).get(node_id, {}).get(
            "betweenness_centrality", 0.0
        )

    def _calculate_closeness(self, node_id: str) -> float:
        """Calculate closeness centrality from shortest-path distances.

        This previously computed ``len(neighbors) / len(neighbors)``, which is
        1.0 for any node with a neighbour and 0.0 otherwise -- a constant that
        conveyed no information at all.
        """
        return self._all_centralities().get(node_id, {}).get("closeness_centrality", 0.0)

    def _calculate_eigenvector(self, node_id: str) -> float:
        """Calculate eigenvector centrality by power iteration.

        This previously returned ``len(neighbors) / 10``, which exceeds 1.0 for
        any node with more than ten neighbours.
        """
        return self._all_centralities().get(node_id, {}).get("eigen_centrality", 0.0)

    def _calculate_pagerank(self, node_id: str) -> float:
        """Calculate PageRank by damped power iteration.

        This previously returned a raw degree ratio with no iteration, damping
        or dangling-mass handling.
        """
        return self._all_centralities().get(node_id, {}).get("page_rank", 0.0)


# Global engine instance
_engine: Optional[NetworkAnalysisEngine] = None


def get_network_analysis_engine() -> NetworkAnalysisEngine:
    """Get the global network analysis engine instance."""
    global _engine
    if _engine is None:
        _engine = NetworkAnalysisEngine()
    return _engine