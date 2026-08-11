"""
Graph Analytics Store - Thread-safe storage with LRU cache
"""

from __future__ import annotations

import threading
from collections import OrderedDict, defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .centrality import all_centralities

from .models import (
    GraphNode,
    GraphEdge,
    CommunityDetection,
    RiskPropagation,
    LateralMovementSimulation,
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
        # Insertion-ordered sets keyed by type value. Dicts are used rather than
        # lists so an element can be dropped from its bucket in O(1) without
        # losing the insertion ordering get_nodes_by_type relies on.
        self._node_index: Dict[str, Dict[str, None]] = defaultdict(dict)
        self._edge_index: Dict[str, Dict[str, None]] = defaultdict(dict)
        # Reverse lookups so a re-add that changes an element's type moves it out
        # of its previous bucket instead of leaving a stale duplicate behind.
        self._node_type_of: Dict[str, str] = {}
        self._edge_type_of: Dict[str, str] = {}
        # How many edges currently join each directed (source, target) pair, so
        # removing one parallel edge does not tear down shared adjacency.
        self._pair_edge_count: Dict[Tuple[str, str], int] = {}
        # Edge ids keyed by the order-independent pair they join, so
        # get_edges_between and get_incident_edges resolve a query without
        # scanning the whole edge map.
        self._edge_pair_index: Dict[Tuple[str, str], Set[str]] = {}
        self._lock = threading.RLock()
        self._cache = LRUCache(max_cache_size)
        self._stats = GraphStats()
        # Running total of len(self._adjacency[n]) across every node, kept in step
        # with each mutation. Recomputing it on every write walked the whole
        # adjacency map, which made ingesting N elements O(N^2).
        self._total_degree = 0
        self._stats_dirty = True
        # Bumped on every mutation so whole-graph centrality results can be
        # memoised and invalidated without rescanning the graph to detect change.
        self._graph_version = 0
        self._centrality_cache: Optional[Dict[str, CentralityMetrics]] = None
        self._centrality_cache_key: Optional[Tuple[int, Optional[int]]] = None

    def add_node(self, node: GraphNode) -> bool:
        """Add a node to the graph."""
        with self._lock:
            self._nodes[node.node_id] = node
            self._cache.put(f"node:{node.node_id}", node)
            self._index_node_type(node.node_id, node.node_type.value)
            self._graph_version += 1
            self._stats_dirty = True
            return True

    def _index_node_type(self, node_id: str, node_type: str) -> None:
        """Record a node under its type, moving it if the type changed."""
        previous = self._node_type_of.get(node_id)
        if previous == node_type:
            return
        if previous is not None:
            self._discard_from_index(self._node_index, previous, node_id)
        self._node_index[node_type][node_id] = None
        self._node_type_of[node_id] = node_type

    def _index_edge_type(self, edge_id: str, edge_type: str) -> None:
        """Record an edge under its type, moving it if the type changed."""
        previous = self._edge_type_of.get(edge_id)
        if previous == edge_type:
            return
        if previous is not None:
            self._discard_from_index(self._edge_index, previous, edge_id)
        self._edge_index[edge_type][edge_id] = None
        self._edge_type_of[edge_id] = edge_type

    @staticmethod
    def _discard_from_index(
        index: Dict[str, Dict[str, None]],
        type_value: str,
        element_id: str,
    ) -> None:
        """Drop an element from a type bucket, removing the bucket once empty."""
        bucket = index.get(type_value)
        if bucket is None:
            return
        bucket.pop(element_id, None)
        if not bucket:
            del index[type_value]

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

    @staticmethod
    def _pair_key(source_id: str, target_id: str) -> Tuple[str, str]:
        """Build the order-independent key used by the edge pair index.

        get_edges_between treats a pair as undirected, so both directions have
        to resolve to the same bucket.
        """
        return (source_id, target_id) if source_id <= target_id else (target_id, source_id)

    def add_edge(self, edge: GraphEdge) -> bool:
        """Add an edge to the graph."""
        with self._lock:
            existing = self._edges.get(edge.edge_id)
            if existing is not None and (
                existing.source_id != edge.source_id
                or existing.target_id != edge.target_id
            ):
                # Re-adding an edge id against a different pair would otherwise
                # strand the old adjacency entry, inflating degree forever.
                self._detach_edge_endpoints(existing)

            self._edges[edge.edge_id] = edge
            self._cache.put(f"edge:{edge.edge_id}", edge)
            pair = (edge.source_id, edge.target_id)
            if existing is None or existing.source_id != edge.source_id or existing.target_id != edge.target_id:
                # Only a genuinely new (id, pair) combination adds to the count.
                self._pair_edge_count[pair] = self._pair_edge_count.get(pair, 0) + 1
            self._edge_pair_index.setdefault(
                self._pair_key(edge.source_id, edge.target_id), set()
            ).add(edge.edge_id)
            # set.add is idempotent, so degree may only grow when the pair is new.
            adjacency = self._adjacency[edge.source_id]
            before = len(adjacency)
            adjacency.add(edge.target_id)
            self._total_degree += len(adjacency) - before
            self._reverse_adjacency[edge.target_id].add(edge.source_id)
            self._index_edge_type(edge.edge_id, edge.edge_type.value)
            self._graph_version += 1
            self._stats_dirty = True
            return True

    def _detach_edge_endpoints(self, edge: GraphEdge) -> None:
        """Drop an edge's adjacency entries when no other edge shares its pair.

        Parallel edges are common in this graph (several transfers between the
        same two accounts), so adjacency may only be torn down once the last
        edge joining the pair is gone. The per-pair counter answers that in O(1)
        rather than rescanning every edge.
        """
        pair = (edge.source_id, edge.target_id)
        self._discard_from_pair_index(self._pair_key(edge.source_id, edge.target_id), edge.edge_id)
        remaining = self._pair_edge_count.get(pair, 0) - 1
        if remaining > 0:
            self._pair_edge_count[pair] = remaining
            return
        self._pair_edge_count.pop(pair, None)

        adjacency = self._adjacency.get(edge.source_id)
        if adjacency and edge.target_id in adjacency:
            adjacency.discard(edge.target_id)
            self._total_degree -= 1
            if not adjacency:
                del self._adjacency[edge.source_id]

        reverse = self._reverse_adjacency.get(edge.target_id)
        if reverse:
            reverse.discard(edge.source_id)
            if not reverse:
                del self._reverse_adjacency[edge.target_id]

    def remove_edge(self, edge_id: str) -> bool:
        """Remove an edge, keeping adjacency, indexes and counters consistent."""
        with self._lock:
            edge = self._edges.pop(edge_id, None)
            if edge is None:
                return False

            self._detach_edge_endpoints(edge)
            edge_type = self._edge_type_of.pop(edge_id, None)
            if edge_type is not None:
                self._discard_from_index(self._edge_index, edge_type, edge_id)
            self._cache.delete(f"edge:{edge_id}")
            self._graph_version += 1
            self._stats_dirty = True
            return True

    def remove_node(self, node_id: str) -> bool:
        """Remove a node together with every edge incident to it."""
        with self._lock:
            if node_id not in self._nodes:
                return False

            incident = [
                edge.edge_id
                for edge in self._edges.values()
                if edge.source_id == node_id or edge.target_id == node_id
            ]
            for edge_id in incident:
                self.remove_edge(edge_id)

            del self._nodes[node_id]
            node_type = self._node_type_of.pop(node_id, None)
            if node_type is not None:
                self._discard_from_index(self._node_index, node_type, node_id)
            self._adjacency.pop(node_id, None)
            self._reverse_adjacency.pop(node_id, None)
            self._cache.delete(f"node:{node_id}")
            self._graph_version += 1
            self._stats_dirty = True
            return True

    def _discard_from_pair_index(self, pair_key: Tuple[str, str], edge_id: str) -> None:
        """Drop an edge from a pair bucket, removing the bucket once empty."""
        bucket = self._edge_pair_index.get(pair_key)
        if bucket is None:
            return
        bucket.discard(edge_id)
        if not bucket:
            del self._edge_pair_index[pair_key]

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
        """Get all edges between two nodes, in either direction."""
        with self._lock:
            edge_ids = self._edge_pair_index.get(self._pair_key(source_id, target_id))
            if not edge_ids:
                return []
            return [self._edges[eid] for eid in edge_ids if eid in self._edges]

    def get_incident_edges(self, node_ids: Set[str], both_endpoints: bool = False) -> List[GraphEdge]:
        """Return every edge touching the given node set.

        Resolved through adjacency rather than by scanning the edge map, so the
        cost tracks the size of the neighbourhood being inspected instead of the
        size of the whole graph.

        Args:
            node_ids: Nodes whose incident edges are wanted.
            both_endpoints: When True, only edges with *both* endpoints inside
                the set are returned; otherwise a single endpoint is enough.
        """
        with self._lock:
            if not node_ids:
                return []

            seen: Dict[str, None] = {}
            edges: List[GraphEdge] = []

            for node_id in node_ids:
                candidates = set(self._adjacency.get(node_id, set()))
                candidates.update(self._reverse_adjacency.get(node_id, set()))

                for other_id in candidates:
                    if both_endpoints and other_id not in node_ids:
                        continue
                    bucket = self._edge_pair_index.get(self._pair_key(node_id, other_id))
                    if not bucket:
                        continue
                    for edge_id in bucket:
                        if edge_id in seen:
                            continue
                        edge = self._edges.get(edge_id)
                        if edge is None:
                            continue
                        if both_endpoints and not (
                            edge.source_id in node_ids and edge.target_id in node_ids
                        ):
                            continue
                        if not both_endpoints and not (
                            edge.source_id in node_ids or edge.target_id in node_ids
                        ):
                            continue
                        seen[edge_id] = None
                        edges.append(edge)

            return edges

    def bfs_traverse(self, start_id: str, max_depth: int = 5, edge_types: Optional[List[EdgeType]] = None) -> List[GraphNode]:
        """Breadth-first search traversal.

        Args:
            start_id: Node to start traversal from.
            max_depth: Maximum number of hops to walk.
            edge_types: When given, only edges whose type is in this list are
                crossed, so the traversal stays inside the filtered subgraph.
        """
        allowed_types = None if edge_types is None else set(edge_types)
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
                    if neighbor_id in visited:
                        continue
                    if allowed_types is not None and not any(
                        edge.edge_type in allowed_types
                        for edge in self.get_edges_between(node_id, neighbor_id)
                    ):
                        continue
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
        """Detect communities in the graph.

        Communities are weakly-connected components, so connectivity is
        symmetric regardless of edge direction: the traversal follows both
        outgoing and incoming edges. This keeps the result independent of node
        insertion/iteration order and prevents sinks from being split out of
        the component they route through.
        """
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

                    neighbors = (
                        self._adjacency.get(current_id, set())
                        | self._reverse_adjacency.get(current_id, set())
                    )
                    for neighbor_id in neighbors:
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
        """Calculate density of a community (undirected view).

        Communities are weakly-connected components, so every directed edge is
        counted once from each endpoint (outgoing + incoming) and the
        denominator is the number of undirected node pairs.
        """
        if len(node_ids) < 2:
            return 0.0

        node_set = set(node_ids)
        directed_edges = 0
        for nid in node_ids:
            directed_edges += len(
                (
                    self._adjacency.get(nid, set())
                    | self._reverse_adjacency.get(nid, set())
                )
                & node_set
            )

        edges = directed_edges // 2
        max_edges = len(node_ids) * (len(node_ids) - 1) // 2
        return edges / max_edges if max_edges > 0 else 0.0

    def _calculate_community_risk(self, node_ids: List[str]) -> float:
        """Calculate risk score for a community."""
        if not node_ids:
            return 0.0

        total_risk = sum(self._nodes[nid].risk_score for nid in node_ids if nid in self._nodes)
        return min(1.0, total_risk / len(node_ids))

    def _combined_adjacency(self) -> Dict[str, Set[str]]:
        """Snapshot the outgoing adjacency for the centrality algorithms.

        Copied under the lock so a long-running whole-graph computation can run
        without holding the store against concurrent writers.
        """
        return {node_id: set(targets) for node_id, targets in self._adjacency.items()}

    def calculate_all_centralities(
        self,
        betweenness_sample_size: Optional[int] = None,
    ) -> Dict[str, CentralityMetrics]:
        """Compute every centrality measure for every node in one pass.

        Each measure is a whole-graph computation, so ranking callers must use
        this rather than calling calculate_centrality once per node.

        Results are memoised against a graph-version counter and reused until
        the next mutation.
        """
        with self._lock:
            cache_key = (self._graph_version, betweenness_sample_size)
            if self._centrality_cache_key == cache_key and self._centrality_cache is not None:
                return self._centrality_cache

            node_ids = list(self._nodes.keys())
            adjacency = self._combined_adjacency()

        scored = all_centralities(adjacency, node_ids, betweenness_sample_size)
        calculated_at = datetime.now(timezone.utc).isoformat()
        metrics = {
            node_id: CentralityMetrics(
                node_id=node_id,
                calculated_at=calculated_at,
                **values,
            )
            for node_id, values in scored.items()
        }

        with self._lock:
            # Only publish if the graph has not moved on while we computed.
            if self._graph_version == cache_key[0]:
                self._centrality_cache = metrics
                self._centrality_cache_key = cache_key
            return metrics

    def calculate_centrality(self, node_id: str) -> CentralityMetrics:
        """Calculate centrality metrics for a node.

        Betweenness, closeness, PageRank and eigenvector centrality are all
        genuinely computed against the stored graph; they previously returned
        hardcoded constants, which made PageRank identical for every node and
        any ranking built on it meaningless.
        """
        with self._lock:
            if len(self._nodes) <= 1:
                return CentralityMetrics(node_id=node_id)
            known = node_id in self._nodes

        if not known:
            return CentralityMetrics(node_id=node_id)

        return self.calculate_all_centralities().get(
            node_id, CentralityMetrics(node_id=node_id)
        )

    def simulate_lateral_movement(self, start_id: str, max_steps: int = 3, min_weight_threshold: float = 0.5) -> List[str]:
        """Simulate lateral movement from a breached node based on edge weights/risks."""
        with self._lock:
            if start_id not in self._nodes:
                return []

            visited = {start_id}
            queue = deque([(start_id, 0)])

            while queue:
                current_id, steps = queue.popleft()
                if steps >= max_steps:
                    continue

                for neighbor_id in self._adjacency.get(current_id, set()):
                    if neighbor_id in visited:
                        continue
                        
                    # Evaluate edge weights to see if movement is possible
                    edges = self.get_edges_between(current_id, neighbor_id)
                    can_traverse = False
                    for edge in edges:
                        # Assuming higher weight means easier to traverse or higher risk connection
                        if edge.weight >= min_weight_threshold:
                            can_traverse = True
                            break
                            
                    if can_traverse:
                        visited.add(neighbor_id)
                        queue.append((neighbor_id, steps + 1))
            
            return list(visited)

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

    def get_all_nodes(self) -> List[GraphNode]:
        """Return a snapshot of every node.

        Materialised under the lock so callers can iterate without racing a
        concurrent write, and without reaching into the store's internals.
        """
        with self._lock:
            return list(self._nodes.values())

    def get_edges_by_type(self, edge_type: EdgeType) -> List[GraphEdge]:
        """Get all edges of a specific type."""
        with self._lock:
            edge_ids = self._edge_index.get(edge_type.value, [])
            return [self._edges[eid] for eid in edge_ids if eid in self._edges]

    def _update_stats(self) -> None:
        """Recompute the cached statistics from the maintained counters.

        Every input is either an O(1) length or the running ``_total_degree``
        counter, so this no longer walks the adjacency map.
        """
        self._stats.total_nodes = len(self._nodes)
        self._stats.total_edges = len(self._edges)
        self._stats.node_types = {
            ntype: len(ids) for ntype, ids in self._node_index.items()
        }
        self._stats.edge_types = {
            etype: len(ids) for etype, ids in self._edge_index.items()
        }

        self._stats.average_degree = (
            self._total_degree / len(self._nodes) if self._nodes else 0.0
        )

        max_edges = len(self._nodes) * (len(self._nodes) - 1)
        self._stats.graph_density = len(self._edges) / max_edges if max_edges > 0 else 0.0
        self._stats_dirty = False

    def recompute_total_degree(self) -> int:
        """Recompute the degree counter from scratch and return it.

        Exposed so callers and tests can assert the incrementally maintained
        counter has not drifted from the underlying adjacency map.
        """
        with self._lock:
            self._total_degree = sum(
                len(neighbors) for neighbors in self._adjacency.values()
            )
            self._stats_dirty = True
            return self._total_degree

    def get_stats(self) -> GraphStats:
        """Get current graph statistics."""
        with self._lock:
            if self._stats_dirty:
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
            self._node_type_of.clear()
            self._edge_type_of.clear()
            self._pair_edge_count.clear()
            self._edge_pair_index.clear()
            self._cache.clear()
            self._stats = GraphStats()
            self._total_degree = 0
            self._stats_dirty = True
            self._graph_version += 1
            self._centrality_cache = None
            self._centrality_cache_key = None


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
