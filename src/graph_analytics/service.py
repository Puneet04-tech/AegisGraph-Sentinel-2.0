"""
Graph Analytics Service - Core business logic
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    GraphNode,
    GraphEdge,
    CommunityDetection,
    RiskPropagation,
    CentralityMetrics,
    PathAnalysis,
    GraphStats,
    NodeType,
    EdgeType,
    AlgorithmType,
)
from .store import get_graph_store, GraphStore


class GraphService:
    """
    Core service for graph analytics operations.
    Provides relationship discovery, fraud ring detection, and risk propagation.
    """

    def __init__(self, store: Optional[GraphStore] = None):
        self._store = store or get_graph_store()
        self._lock = threading.RLock()

    def add_entity(
        self,
        entity_id: str,
        entity_type: str,
        label: str = "",
        properties: Optional[Dict[str, Any]] = None,
        risk_score: float = 0.0,
        tags: Optional[List[str]] = None,
    ) -> GraphNode:
        """Add an entity to the graph."""
        with self._lock:
            try:
                node_type = NodeType(entity_type)
            except ValueError:
                node_type = NodeType.ENTITY

            node = GraphNode(
                node_id=entity_id,
                node_type=node_type,
                label=label,
                properties=properties or {},
                risk_score=risk_score,
                tags=tags or [],
            )
            self._store.add_node(node)
            return node

    def link_entities(
        self,
        source_id: str,
        target_id: str,
        relationship: str = "linked_to",
        weight: float = 1.0,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Optional[GraphEdge]:
        """Link two entities in the graph."""
        with self._lock:
            source = self._store.get_node(source_id)
            target = self._store.get_node(target_id)

            if not source or not target:
                return None

            try:
                edge_type = EdgeType(relationship)
            except ValueError:
                edge_type = EdgeType.LINKED_TO

            edge = GraphEdge(
                source_id=source_id,
                target_id=target_id,
                edge_type=edge_type,
                weight=weight,
                properties=properties or {},
            )
            self._store.add_edge(edge)
            return edge

    def discover_relationships(
        self,
        entity_id: str,
        max_depth: int = 3,
    ) -> List[GraphNode]:
        """Discover relationships for an entity."""
        return self._store.bfs_traverse(entity_id, max_depth=max_depth)

    def detect_fraud_rings(
        self,
        min_size: int = 3,
        algorithm: AlgorithmType = AlgorithmType.LOUVAIN,
    ) -> List[CommunityDetection]:
        """Detect fraud rings using community detection."""
        communities = self._store.detect_communities(algorithm)
        return [c for c in communities if c.size >= min_size]

    def propagate_risk(
        self,
        source_id: str,
        max_depth: int = 5,
        decay: float = 0.8,
    ) -> RiskPropagation:
        """Propagate risk through connected entities."""
        return self._store.propagate_risk(source_id, max_depth, decay)

    def analyze_paths(
        self,
        source_id: str,
        target_id: str,
    ) -> Optional[PathAnalysis]:
        """Analyze paths between two entities."""
        path = self._store.find_shortest_path(source_id, target_id)
        if not path:
            return None

        edges = []
        total_weight = 0.0
        for i in range(len(path) - 1):
            edge_list = self._store.get_edges_between(path[i], path[i + 1])
            if edge_list:
                edges.append(edge_list[0])
                total_weight += edge_list[0].weight

        return PathAnalysis(
            source_id=source_id,
            target_id=target_id,
            path=path,
            path_length=len(path) - 1,
            total_weight=total_weight,
            edges=edges,
        )

    def calculate_entity_centrality(self, entity_id: str) -> CentralityMetrics:
        """Calculate centrality metrics for an entity."""
        return self._store.calculate_centrality(entity_id)

    def get_entity_network(self, entity_id: str, depth: int = 2) -> Dict[str, Any]:
        """Get the full network around an entity."""
        nodes = self._store.bfs_traverse(entity_id, max_depth=depth)
        node_ids = {n.node_id for n in nodes}

        edges = []
        for eid, edge in self._store._edges.items():
            if edge.source_id in node_ids and edge.target_id in node_ids:
                edges.append(edge)

        return {
            "center": entity_id,
            "nodes": [n.to_dict() for n in nodes],
            "edges": [e.to_dict() for e in edges],
            "depth": depth,
        }

    def find_common_neighbors(self, entity_id1: str, entity_id2: str) -> List[GraphNode]:
        """Find common neighbors between two entities."""
        neighbors1 = set(n.node_id for n in self._store.get_neighbors(entity_id1))
        neighbors2 = set(n.node_id for n in self._store.get_neighbors(entity_id2))
        common_ids = neighbors1 & neighbors2

        return [self._store.get_node(nid) for nid in common_ids if self._store.get_node(nid)]

    def find_critical_entities(self, min_centrality: float = 0.1) -> List[CentralityMetrics]:
        """Find critical entities based on centrality."""
        critical = []
        for node_id in self._store._nodes:
            metrics = self._store.calculate_centrality(node_id)
            if metrics.degree_centrality >= min_centrality or metrics.page_rank >= min_centrality:
                critical.append(metrics)
        return sorted(critical, key=lambda x: x.page_rank, reverse=True)

    def get_connection_strength(self, entity_id1: str, entity_id2: str) -> float:
        """Calculate connection strength between two entities."""
        path = self._store.find_shortest_path(entity_id1, entity_id2)
        if not path:
            return 0.0

        edges = self._store.get_edges_between(entity_id1, entity_id2)
        if edges:
            return max(e.weight for e in edges)

        return 1.0 / len(path)

    def analyze_influence(
        self,
        entity_id: str,
        max_depth: int = 3,
    ) -> Dict[str, Any]:
        """Analyze the influence of an entity."""
        nodes = self._store.dfs_traverse(entity_id, max_depth=max_depth)
        metrics = self._store.calculate_centrality(entity_id)

        total_risk = sum(n.risk_score for n in nodes)
        avg_risk = total_risk / len(nodes) if nodes else 0.0

        return {
            "entity_id": entity_id,
            "influence_score": metrics.page_rank,
            "reachable_entities": len(nodes),
            "average_risk": avg_risk,
            "max_depth": max_depth,
        }

    def search_by_properties(
        self,
        properties: Dict[str, Any],
        node_type: Optional[str] = None,
    ) -> List[GraphNode]:
        """Search entities by properties."""
        results = []

        for node in self._store._nodes.values():
            if node_type and node.node_type.value != node_type:
                continue

            match = all(
                node.properties.get(k) == v
                for k, v in properties.items()
            )
            if match:
                results.append(node)

        return results

    def get_graph_statistics(self) -> GraphStats:
        """Get comprehensive graph statistics."""
        return self._store.get_stats()

    def export_subgraph(
        self,
        center_id: str,
        depth: int = 2,
    ) -> Dict[str, Any]:
        """Export a subgraph centered on an entity."""
        nodes = self._store.bfs_traverse(center_id, max_depth=depth)
        node_ids = {n.node_id for n in nodes}

        edges = []
        for edge in self._store._edges.values():
            if edge.source_id in node_ids or edge.target_id in node_ids:
                edges.append(edge)

        return {
            "center": center_id,
            "nodes": [n.to_dict() for n in nodes],
            "edges": [e.to_dict() for e in edges],
            "stats": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
            },
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }


_graph_service: Optional[GraphService] = None
_service_lock = threading.Lock()


def get_graph_service() -> GraphService:
    """Get the singleton GraphService instance."""
    global _graph_service
    with _service_lock:
        if _graph_service is None:
            _graph_service = GraphService()
        return _graph_service


def reset_graph_service() -> None:
    """Reset the singleton service (for testing)."""
    global _graph_service
    with _service_lock:
        _graph_service = None
