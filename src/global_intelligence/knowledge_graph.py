"""
Knowledge Graph Engine for entity relationships and graph traversal.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid

from .models import (
    EntityType,
    FederatedEntity,
    FraudNetwork,
    KnowledgeGraphNode,
    KnowledgeGraphEdge,
    NetworkType,
    ThreatLevel,
)
from .store import GlobalIntelligenceStore, get_global_intelligence_store


class TraversalType(str, Enum):
    """Types of graph traversal."""
    BFS = "breadth_first"
    DFS = "depth_first"
    DIJKSTRA = "dijkstra"
    BELLMAN_FORD = "bellman_ford"


class RelationshipType(str, Enum):
    """Types of relationships between entities."""
    LINKED_TO = "linked_to"
    SHARES_IP = "shares_ip"
    SHARES_DEVICE = "shares_device"
    SHARES_ACCOUNT = "shares_account"
    TRANSFERRED_TO = "transferred_to"
    RECEIVED_FROM = "received_from"
    SIMILAR_TO = "similar_to"
    PART_OF_NETWORK = "part_of_network"
    CORRELATED_WITH = "correlated_with"


@dataclass
class GraphTraversalResult:
    """Result of graph traversal operation."""
    traversal_id: str
    start_node_id: str
    end_node_id: Optional[str]
    nodes: List[KnowledgeGraphNode]
    edges: List[KnowledgeGraphEdge]
    paths: List[List[str]]
    depth_reached: int
    nodes_visited: int
    execution_time_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PatternMatch:
    """Result of pattern matching in graph."""
    match_id: str
    pattern_type: str
    matched_nodes: List[str]
    matched_edges: List[str]
    confidence: float
    discovered_at: datetime


@dataclass
class GraphStatistics:
    """Statistics about the knowledge graph."""
    total_nodes: int
    total_edges: int
    avg_degree: float
    max_degree: int
    avg_clustering: float
    density: float
    connected_components: int
    entities_by_type: Dict[str, int]
    relationships_by_type: Dict[str, int]


class KnowledgeGraphEngine:
    """
    Knowledge graph engine for entity relationships and fraud network analysis.

    Handles:
    - Entity relationship management
    - Graph traversal algorithms
    - Pattern matching
    - Fraud ring detection
    - Attack chain discovery
    """

    def __init__(self, store: Optional[GlobalIntelligenceStore] = None):
        self._store = store or get_global_intelligence_store()
        self._adjacency: Dict[str, Dict[str, List[str]]] = defaultdict(
            lambda: defaultdict(list)
        )  # node -> {relationship -> [target_nodes]}

    def add_entity(
        self,
        entity_id: str,
        entity_type: EntityType,
        properties: Dict[str, Any],
        labels: Optional[List[str]] = None,
    ) -> KnowledgeGraphNode:
        """Add an entity to the graph."""
        node = KnowledgeGraphNode(
            node_id=entity_id,
            entity_type=entity_type,
            properties=properties,
            labels=labels or [],
            risk_score=properties.get("risk_score", 0.0),
            threat_level=ThreatLevel(properties.get("threat_level", "unknown")),
        )
        self._store.store_graph_node(node)
        return node

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        relationship_type: str,
        properties: Optional[Dict[str, Any]] = None,
        weight: float = 1.0,
        confidence: float = 1.0,
    ) -> KnowledgeGraphEdge:
        """Add a relationship between entities."""
        # Ensure nodes exist
        source = self._store.get_graph_node(source_id)
        target = self._store.get_graph_node(target_id)
        if not source or not target:
            raise ValueError("Source or target node not found")

        edge_id = str(uuid.uuid4())
        edge = KnowledgeGraphEdge(
            edge_id=edge_id,
            source_id=source_id,
            target_id=target_id,
            relationship_type=relationship_type,
            properties=properties or {},
            weight=weight,
            confidence=confidence,
        )

        self._store.store_graph_edge(edge)
        self._adjacency[source_id][relationship_type].append(target_id)
        return edge

    def traverse(
        self,
        start_node_id: str,
        traversal_type: TraversalType = TraversalType.BFS,
        max_depth: int = 3,
        relationship_types: Optional[List[str]] = None,
        node_filter: Optional[Callable[[KnowledgeGraphNode], bool]] = None,
    ) -> GraphTraversalResult:
        """Traverse the graph from a starting node."""
        import time

        start_time = time.time()
        traversal_id = str(uuid.uuid4())

        visited: Set[str] = set()
        nodes: List[KnowledgeGraphNode] = []
        edges: List[KnowledgeGraphEdge] = []
        paths: List[List[str]] = []

        # Get start node
        start_node = self._store.get_graph_node(start_node_id)
        if not start_node:
            return GraphTraversalResult(
                traversal_id=traversal_id,
                start_node_id=start_node_id,
                end_node_id=None,
                nodes=[],
                edges=[],
                paths=[],
                depth_reached=0,
                nodes_visited=0,
                execution_time_ms=(time.time() - start_time) * 1000,
            )

        if traversal_type == TraversalType.BFS:
            visited, nodes, edges, paths = self._bfs_traversal(
                start_node,
                max_depth,
                relationship_types,
                node_filter,
            )
        elif traversal_type == TraversalType.DFS:
            visited, nodes, edges, paths = self._dfs_traversal(
                start_node,
                max_depth,
                relationship_types,
                node_filter,
            )

        depth = max_depth if visited else 0

        return GraphTraversalResult(
            traversal_id=traversal_id,
            start_node_id=start_node_id,
            end_node_id=None,
            nodes=nodes,
            edges=edges,
            paths=paths,
            depth_reached=depth,
            nodes_visited=len(visited),
            execution_time_ms=(time.time() - start_time) * 1000,
        )

    def _bfs_traversal(
        self,
        start_node: KnowledgeGraphNode,
        max_depth: int,
        relationship_types: Optional[List[str]],
        node_filter: Optional[Callable],
    ) -> Tuple[Set[str], List[KnowledgeGraphNode], List[KnowledgeGraphEdge], List[List[str]]]:
        """Breadth-first search traversal."""
        visited: Set[str] = {start_node.node_id}
        queue = deque([(start_node.node_id, 0, [start_node.node_id])])
        nodes = [start_node]
        edges = []
        paths = []

        while queue:
            current_id, depth, path = queue.popleft()

            if depth >= max_depth:
                continue

            current_edges = self._store.get_node_edges(current_id)

            for edge in current_edges:
                # Filter by relationship type
                if relationship_types and edge.relationship_type not in relationship_types:
                    continue

                # Determine target node
                target_id = edge.target_id if edge.source_id == current_id else edge.source_id

                if target_id not in visited:
                    visited.add(target_id)
                    new_path = path + [target_id]

                    target_node = self._store.get_graph_node(target_id)
                    if target_node:
                        # Apply node filter
                        if node_filter and not node_filter(target_node):
                            continue

                        nodes.append(target_node)
                        edges.append(edge)
                        queue.append((target_id, depth + 1, new_path))

                        if depth + 1 == max_depth:
                            paths.append(new_path)

        return visited, nodes, edges, paths

    def _dfs_traversal(
        self,
        start_node: KnowledgeGraphNode,
        max_depth: int,
        relationship_types: Optional[List[str]],
        node_filter: Optional[Callable],
    ) -> Tuple[Set[str], List[KnowledgeGraphNode], List[KnowledgeGraphEdge], List[List[str]]]:
        """Depth-first search traversal."""
        visited: Set[str] = set()
        nodes = []
        edges = []

        def dfs(current_id: str, depth: int, path: List[str]):
            if depth >= max_depth or current_id in visited:
                return

            visited.add(current_id)

            if depth > 0:
                current_node = self._store.get_graph_node(current_id)
                if current_node:
                    if node_filter and not node_filter(current_node):
                        visited.discard(current_id)
                        return
                    nodes.append(current_node)

            current_edges = self._store.get_node_edges(current_id)

            for edge in current_edges:
                if relationship_types and edge.relationship_type not in relationship_types:
                    continue

                target_id = edge.target_id if edge.source_id == current_id else edge.source_id

                if target_id not in visited:
                    edges.append(edge)
                    dfs(target_id, depth + 1, path + [target_id])

        dfs(start_node.node_id, 0, [start_node.node_id])

        return visited, nodes, edges, []

    def find_shortest_path(
        self, source_id: str, target_id: str, max_hops: int = 10
    ) -> Optional[List[str]]:
        """Find shortest path between two nodes."""
        if source_id == target_id:
            return [source_id]

        visited: Set[str] = {source_id}
        queue = deque([(source_id, [source_id])])

        while queue:
            current, path = queue.popleft()

            if len(path) > max_hops:
                continue

            for edge in self._store.get_node_edges(current):
                target = edge.target_id if edge.source_id == current else edge.source_id

                if target == target_id:
                    return path + [target]

                if target not in visited:
                    visited.add(target)
                    queue.append((target, path + [target]))

        return None

    def find_connected_components(self) -> List[List[str]]:
        """Find all connected components in the graph."""
        visited: Set[str] = set()
        components: List[List[str]] = []

        all_nodes = list(self._store._graph_nodes.keys())

        for node_id in all_nodes:
            if node_id in visited:
                continue

            component = []
            queue = deque([node_id])

            while queue:
                current = queue.popleft()
                if current in visited:
                    continue

                visited.add(current)
                component.append(current)

                for edge in self._store.get_node_edges(current):
                    target = edge.target_id if edge.source_id == current else edge.source_id
                    if target not in visited:
                        queue.append(target)

            if component:
                components.append(component)

        return components

    def detect_communities(self, min_size: int = 3) -> List[List[str]]:
        """Detect communities using simple label propagation."""
        all_nodes = list(self._store._graph_nodes.keys())
        if not all_nodes:
            return []

        # Initialize labels
        labels = {node: node for node in all_nodes}
        changed = True

        # Label propagation iterations
        max_iterations = 10
        iteration = 0

        while changed and iteration < max_iterations:
            changed = False
            iteration += 1

            for node_id in all_nodes:
                neighbors = []
                for edge in self._store.get_node_edges(node_id):
                    neighbor = edge.target_id if edge.source_id == node_id else edge.source_id
                    neighbors.append(neighbor)

                if neighbors:
                    neighbor_labels = [labels[n] for n in neighbors]
                    most_common = max(set(neighbor_labels), key=neighbor_labels.count)
                    if most_common != labels[node_id]:
                        labels[node_id] = most_common
                        changed = True

        # Group by label
        communities: Dict[str, List[str]] = defaultdict(list)
        for node_id, label in labels.items():
            communities[label].append(node_id)

        # Filter by minimum size
        return [c for c in communities.values() if len(c) >= min_size]

    def get_graph_statistics(self) -> GraphStatistics:
        """Get statistics about the knowledge graph."""
        nodes = self._store._graph_nodes
        edges = self._store._graph_edges

        if not nodes:
            return GraphStatistics(
                total_nodes=0,
                total_edges=0,
                avg_degree=0.0,
                max_degree=0,
                avg_clustering=0.0,
                density=0.0,
                connected_components=0,
                entities_by_type={},
                relationships_by_type={},
            )

        # Calculate degrees
        degrees: Dict[str, int] = defaultdict(int)
        for edge in edges.values():
            degrees[edge.source_id] += 1
            degrees[edge.target_id] += 1

        # Count by type
        entities_by_type: Dict[str, int] = defaultdict(int)
        for node in nodes.values():
            entities_by_type[node.entity_type.value] += 1

        relationships_by_type: Dict[str, int] = defaultdict(int)
        for edge in edges.values():
            relationships_by_type[edge.relationship_type] += 1

        # Calculate connected components
        components = self.find_connected_components()

        n = len(nodes)
        e = len(edges)
        avg_degree = sum(degrees.values()) / n if n > 0 else 0
        max_degree = max(degrees.values()) if degrees else 0
        density = (2 * e) / (n * (n - 1)) if n > 1 else 0

        return GraphStatistics(
            total_nodes=n,
            total_edges=e,
            avg_degree=avg_degree,
            max_degree=max_degree,
            avg_clustering=0.0,  # Simplified
            density=density,
            connected_components=len(components),
            entities_by_type=dict(entities_by_type),
            relationships_by_type=dict(relationships_by_type),
        )


# Global engine instance
_engine: Optional[KnowledgeGraphEngine] = None


def get_knowledge_graph_engine() -> KnowledgeGraphEngine:
    """Get the global knowledge graph engine instance."""
    global _engine
    if _engine is None:
        _engine = KnowledgeGraphEngine()
    return _engine