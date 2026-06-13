"""
Graph Analytics Store - Thread-safe storage with LRU cache
"""

from __future__ import annotations

import threading
from collections import OrderedDict, defaultdict, deque
from typing import Any, Dict, List, Optional, Set

from .models import (
    GraphNode,
    GraphEdge,
    CommunityDetection,
    RiskPropagation,
    CentralityMetrics,
    GraphStats,
    NodeType,
    EdgeType,
    AlgorithmType,
)


class LRUCache:
    """Thread-safe LRU cache with bounded size."""

    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.cache: OrderedDict = OrderedDict()
        self.lock = threading.RLock()

    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
                return self.cache[key]
            return None

    def put(self, key: str, value: Any) -> None:
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = value
            if len(self.cache) > self.max_size:
                self.cache.popitem(last=False)

    def delete(self, key: str) -> None:
        with self.lock:
            if key in self.cache:
                del self.cache[key]

    def clear(self) -> None:
        with self.lock:
            self.cache.clear()


class GraphStore:
    """
    Thread-safe storage for graph analytics data.
    Uses adjacency list representation for efficient graph traversal.
    """

    def __init__(self, max_cache_size: int = 10000):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}
        self._adjacency: Dict[str, Set[str]] = defaultdict(set)
        self._reverse_adjacency: Dict[str, Set[str]] = defaultdict(set)
        self._node_index: Dict[str, List[str]] = defaultdict(list)
        self._edge_index: Dict[str, List[str]] = defaultdict(list)
        self._lock = threading.RLock()
        self._cache = LRUCache(max_cache_size)
        self._stats = GraphStats()

    def add_node(self, node: GraphNode) -> bool:
        """Add a node to the graph."""
        with self._lock:
            self._nodes[node.node_id] = node
            self._cache.put(f"node:{node.node_id}", node)
            self._node_index[node.node_type.value].append(node.node_id)
            self._update_stats()
            return True

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get a node by ID."""
        cached = self._cache.get(f"node:{node_id}")
        if cached:
            return cached

        with self._lock:
            node = self._nodes.get(node_id)
            if node:
                self._cache.put(f"node:{node_id}", node)
            return node

    def add_edge(self, edge: GraphEdge) -> bool:
        """Add an edge to the graph."""
        with self._lock:
            self._edges[edge.edge_id] = edge
            self._cache.put(f"edge:{edge.edge_id}", edge)
            self._adjacency[edge.source_id].add(edge.target_id)
            self._reverse_adjacency[edge.target_id].add(edge.source_id)
            self._edge_index[edge.edge_type.value].append(edge.edge_id)
            self._update_stats()
            return True

    def get_edge(self, edge_id: str) -> Optional[GraphEdge]:
        """Get an edge by ID."""
        cached = self._cache.get(f"edge:{edge_id}")
        if cached:
            return cached

        with self._lock:
            return self._edges.get(edge_id)

    def get_neighbors(self, node_id: str, direction: str = "both") -> List[GraphNode]:
        """Get neighboring nodes."""
        with self._lock:
            neighbors = []
            neighbor_ids = set()

            if direction in ("both", "outgoing"):
                neighbor_ids.update(self._adjacency.get(node_id, set()))
            if direction in ("both", "incoming"):
                neighbor_ids.update(self._reverse_adjacency.get(node_id, set()))

            for nid in neighbor_ids:
                node = self._nodes.get(nid)
                if node:
                    neighbors.append(node)

            return neighbors

    def get_edges_between(self, source_id: str, target_id: str) -> List[GraphEdge]:
        """Get all edges between two nodes."""
        with self._lock:
            edges = []
            for edge in self._edges.values():
                if (edge.source_id == source_id and edge.target_id == target_id) or \
                   (edge.source_id == target_id and edge.target_id == source_id):
                    edges.append(edge)
            return edges

    def bfs_traverse(self, start_id: str, max_depth: int = 5, edge_types: Optional[List[EdgeType]] = None) -> List[GraphNode]:
        """Breadth-first search traversal."""
        with self._lock:
            visited = set()
            queue = deque([(start_id, 0)])
            result = []

            while queue:
                node_id, depth = queue.popleft()
                if node_id in visited or depth > max_depth:
                    continue

                visited.add(node_id)
                node = self._nodes.get(node_id)
                if node:
                    result.append(node)

                for neighbor_id in self._adjacency.get(node_id, set()):
                    if neighbor_id not in visited:
                        queue.append((neighbor_id, depth + 1))

            return result

    def dfs_traverse(self, start_id: str, max_depth: int = 5) -> List[GraphNode]:
        """Depth-first search traversal."""
        with self._lock:
            visited = set()
            stack = [(start_id, 0)]
            result = []

            while stack:
                node_id, depth = stack.pop()
                if node_id in visited or depth > max_depth:
                    continue

                visited.add(node_id)
                node = self._nodes.get(node_id)
                if node:
                    result.append(node)

                for neighbor_id in self._adjacency.get(node_id, set()):
                    if neighbor_id not in visited:
                        stack.append((neighbor_id, depth + 1))

            return result

    def find_shortest_path(self, source_id: str, target_id: str) -> Optional[List[str]]:
        """Find shortest path using BFS."""
        with self._lock:
            if source_id == target_id:
                return [source_id]

            visited = {source_id}
            queue = deque([(source_id, [source_id])])

            while queue:
                node_id, path = queue.popleft()

                for neighbor_id in self._adjacency.get(node_id, set()):
                    if neighbor_id == target_id:
                        return path + [neighbor_id]

                    if neighbor_id not in visited:
                        visited.add(neighbor_id)
                        queue.append((neighbor_id, path + [neighbor_id]))

            return None

    def detect_communities(self, algorithm: AlgorithmType = AlgorithmType.LOUVAIN) -> List[CommunityDetection]:
        """Detect communities in the graph."""
        with self._lock:
            communities = []
            visited = set()

            for node_id in self._nodes:
                if node_id in visited:
                    continue

                community_nodes = []
                queue = deque([node_id])

                while queue:
                    current_id = queue.popleft()
                    if current_id in visited:
                        continue

                    visited.add(current_id)
                    community_nodes.append(current_id)

                    for neighbor_id in self._adjacency.get(current_id, set()):
                        if neighbor_id not in visited:
                            queue.append(neighbor_id)

                if community_nodes:
                    community = CommunityDetection(
                        algorithm=algorithm,
                        node_ids=community_nodes,
                        size=len(community_nodes),
                        density=self._calculate_density(community_nodes),
                        risk_score=self._calculate_community_risk(community_nodes),
                    )
                    communities.append(community)

            return communities

    def _calculate_density(self, node_ids: List[str]) -> float:
        """Calculate density of a community."""
        if len(node_ids) < 2:
            return 0.0

        edges = 0
        for nid in node_ids:
            edges += len(self._adjacency.get(nid, set()) & set(node_ids))

        max_edges = len(node_ids) * (len(node_ids) - 1)
        return edges / max_edges if max_edges > 0 else 0.0

    def _calculate_community_risk(self, node_ids: List[str]) -> float:
        """Calculate risk score for a community."""
        if not node_ids:
            return 0.0

        total_risk = sum(self._nodes[nid].risk_score for nid in node_ids if nid in self._nodes)
        return min(1.0, total_risk / len(node_ids))

    def calculate_centrality(self, node_id: str) -> CentralityMetrics:
        """Calculate centrality metrics for a node."""
        with self._lock:
            total_nodes = len(self._nodes)
            if total_nodes <= 1:
                return CentralityMetrics(node_id=node_id)

            degree = len(self._adjacency.get(node_id, set())) + len(self._reverse_adjacency.get(node_id, set()))
            degree_centrality = degree / (total_nodes - 1) if total_nodes > 1 else 0.0

            return CentralityMetrics(
                node_id=node_id,
                degree_centrality=degree_centrality,
                betweenness_centrality=0.0,
                closeness_centrality=0.0,
                page_rank=1.0 / total_nodes,
                eigen_centrality=0.0,
            )

    def propagate_risk(self, source_id: str, max_depth: int = 5, decay_factor: float = 0.8) -> RiskPropagation:
        """Propagate risk through the graph."""
        with self._lock:
            source = self._nodes.get(source_id)
            if not source:
                return RiskPropagation(source_node_id=source_id)

            risk_scores = {source_id: source.risk_score}
            visited = {source_id}
            queue = deque([(source_id, 1)])

            while queue:
                node_id, depth = queue.popleft()
                if depth > max_depth:
                    continue

                current_risk = risk_scores.get(node_id, 0.0)
                propagated_risk = current_risk * decay_factor

                for neighbor_id in self._adjacency.get(node_id, set()):
                    if neighbor_id not in visited:
                        visited.add(neighbor_id)
                        risk_scores[neighbor_id] = propagated_risk
                        queue.append((neighbor_id, depth + 1))

                    if neighbor_id in risk_scores:
                        risk_scores[neighbor_id] = max(risk_scores[neighbor_id], propagated_risk)

            return RiskPropagation(
                source_node_id=source_id,
                affected_nodes=list(visited),
                propagation_depth=max_depth,
                risk_scores=risk_scores,
                propagation_path=list(visited),
            )

    def get_nodes_by_type(self, node_type: NodeType) -> List[GraphNode]:
        """Get all nodes of a specific type."""
        with self._lock:
            node_ids = self._node_index.get(node_type.value, [])
            return [self._nodes[nid] for nid in node_ids if nid in self._nodes]

    def get_edges_by_type(self, edge_type: EdgeType) -> List[GraphEdge]:
        """Get all edges of a specific type."""
        with self._lock:
            edge_ids = self._edge_index.get(edge_type.value, [])
            return [self._edges[eid] for eid in edge_ids if eid in self._edges]

    def _update_stats(self) -> None:
        """Update graph statistics."""
        self._stats.total_nodes = len(self._nodes)
        self._stats.total_edges = len(self._edges)
        self._stats.node_types = {
            ntype: len(ids) for ntype, ids in self._node_index.items()
        }
        self._stats.edge_types = {
            etype: len(ids) for etype, ids in self._edge_index.items()
        }

        total_degree = sum(len(neighbors) for neighbors in self._adjacency.values())
        self._stats.average_degree = total_degree / len(self._nodes) if self._nodes else 0.0

        max_edges = len(self._nodes) * (len(self._nodes) - 1)
        self._stats.graph_density = len(self._edges) / max_edges if max_edges > 0 else 0.0

    def get_stats(self) -> GraphStats:
        """Get current graph statistics."""
        with self._lock:
            self._update_stats()
            return self._stats

    def clear(self) -> None:
        """Clear all stored data."""
        with self._lock:
            self._nodes.clear()
            self._edges.clear()
            self._adjacency.clear()
            self._reverse_adjacency.clear()
            self._node_index.clear()
            self._edge_index.clear()
            self._cache.clear()
            self._stats = GraphStats()


_graph_store: Optional[GraphStore] = None
_store_lock = threading.Lock()


def get_graph_store() -> GraphStore:
    """Get the singleton GraphStore instance."""
    global _graph_store
    with _store_lock:
        if _graph_store is None:
            _graph_store = GraphStore()
        return _graph_store


def reset_graph_store() -> None:
    """Reset the singleton store (for testing)."""
    global _graph_store
    with _store_lock:
        if _graph_store:
            _graph_store.clear()
        _graph_store = None
