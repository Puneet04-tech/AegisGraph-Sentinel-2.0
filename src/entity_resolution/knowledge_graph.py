"""
Knowledge Graph Engine for storing and querying entity relationships.

Provides:
    KnowledgeGraph: Graph-based entity relationship storage and traversal
    get_knowledge_graph: Singleton getter for the knowledge graph
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
import logging
import uuid

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None

from .models import Entity, EntityRelationship, EntityType, RelationshipType
from .store import EntityStore, get_entity_store

logger = logging.getLogger(__name__)


class TraversalOrder(str, Enum):
    """Traversal order for graph queries."""
    BREADTH_FIRST = "BREADTH_FIRST"
    DEPTH_FIRST = "DEPTH_FIRST"


@dataclass
class GraphNode:
    """Represents a node in the knowledge graph."""
    entity_id: str
    entity_type: EntityType
    attributes: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Represents an edge in the knowledge graph."""
    source_id: str
    target_id: str
    relationship_type: RelationshipType
    confidence_score: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphQueryResult:
    """Result of a graph query."""
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    path: List[str]
    depth: int
    total_nodes: int
    total_edges: int


class KnowledgeGraph:
    """Knowledge Graph Engine for entity relationship storage and traversal.
    
    This engine provides:
    - Graph node and edge creation
    - Relationship storage and indexing
    - Graph traversal (BFS, DFS)
    - Graph queries and analysis
    
    Attributes:
        store: Entity store for persistence
        use_networkx: Whether to use NetworkX for advanced graph operations
    """
    
    def __init__(self, store: Optional[EntityStore] = None, use_networkx: bool = True):
        """Initialize the knowledge graph.
        
        Args:
            store: Optional entity store (creates singleton if not provided)
            use_networkx: Whether to use NetworkX for advanced graph operations
        """
        self._store = store or get_entity_store()
        self._use_networkx = use_networkx and NETWORKX_AVAILABLE
        
        if self._use_networkx:
            self._nx_graph = nx.Graph()
        else:
            self._nx_graph = None
        
        self._graph_lock = Lock()
        logger.info(f"KnowledgeGraph initialized with NetworkX support: {self._use_networkx}")
    
    def _sync_to_networkx(self) -> None:
        """Synchronize the store data to NetworkX graph."""
        if not self._use_networkx or self._nx_graph is None:
            return
        
        with self._store._entity_lock:
            for entity_id, entity in self._store._entities.items():
                self._nx_graph.add_node(
                    entity_id,
                    entity_type=entity.entity_type.value,
                    risk_score=entity.risk_score,
                    attributes=entity.attributes,
                )
        
        with self._store._relationship_lock:
            for rel_id, rel in self._store._relationships.items():
                self._nx_graph.add_edge(
                    rel.source_id,
                    rel.target_id,
                    relationship_type=rel.relationship_type.value,
                    confidence_score=rel.confidence_score,
                    metadata=rel.metadata,
                )
    
    def add_node(self, entity: Entity) -> GraphNode:
        """Add a node to the graph.
        
        Args:
            entity: Entity to add as a node
            
        Returns:
            The created GraphNode
        """
        node = GraphNode(
            entity_id=entity.id,
            entity_type=entity.entity_type,
            attributes=entity.attributes,
            risk_score=entity.risk_score,
            metadata=entity.metadata,
        )
        
        # Store the entity
        self._store.store_entity(entity)
        
        # Add to NetworkX if available
        if self._use_networkx and self._nx_graph is not None:
            with self._graph_lock:
                self._nx_graph.add_node(
                    entity.id,
                    entity_type=entity.entity_type.value,
                    risk_score=entity.risk_score,
                    attributes=entity.attributes,
                )
        
        logger.debug(f"Added node {entity.id} to knowledge graph")
        return node
    
    def add_edge(self, relationship: EntityRelationship) -> GraphEdge:
        """Add an edge to the graph.
        
        Args:
            relationship: Relationship to add as an edge
            
        Returns:
            The created GraphEdge
        """
        edge = GraphEdge(
            source_id=relationship.source_id,
            target_id=relationship.target_id,
            relationship_type=relationship.relationship_type,
            confidence_score=relationship.confidence_score,
            metadata=relationship.metadata,
        )
        
        # Store the relationship
        self._store.store_relationship(relationship)
        
        # Add to NetworkX if available
        if self._use_networkx and self._nx_graph is not None:
            with self._graph_lock:
                self._nx_graph.add_edge(
                    relationship.source_id,
                    relationship.target_id,
                    relationship_type=relationship.relationship_type.value,
                    confidence_score=relationship.confidence_score,
                    metadata=relationship.metadata,
                )
        
        logger.debug(f"Added edge {relationship.source_id} -> {relationship.target_id}")
        return edge
    
    def remove_node(self, entity_id: str) -> bool:
        """Remove a node from the graph.
        
        Args:
            entity_id: ID of the entity to remove
            
        Returns:
            True if removed, False if not found
        """
        result = self._store.delete_entity(entity_id)
        
        if result and self._use_networkx and self._nx_graph is not None:
            with self._graph_lock:
                if entity_id in self._nx_graph:
                    self._nx_graph.remove_node(entity_id)
        
        return result
    
    def remove_edge(self, source_id: str, target_id: str, relationship_type: Optional[RelationshipType] = None) -> bool:
        """Remove an edge from the graph.
        
        Args:
            source_id: Source entity ID
            target_id: Target entity ID
            relationship_type: Optional relationship type
            
        Returns:
            True if removed, False if not found
        """
        rel = self._store.get_relationship(source_id, target_id, relationship_type)
        if rel is None:
            return False
        
        # Delete from store
        rel_id = f"{source_id}:{target_id}:{relationship_type.value if relationship_type else rel.relationship_type.value}"
        with self._store._relationship_lock:
            if rel_id in self._store._relationships:
                del self._store._relationships[rel_id]
        
        # Remove from NetworkX if available
        if self._use_networkx and self._nx_graph is not None:
            with self._graph_lock:
                if self._nx_graph.has_edge(source_id, target_id):
                    self._nx_graph.remove_edge(source_id, target_id)
        
        return True
    
    def get_node(self, entity_id: str) -> Optional[GraphNode]:
        """Get a node by ID.
        
        Args:
            entity_id: ID of the entity
            
        Returns:
            The GraphNode if found, None otherwise
        """
        entity = self._store.get_entity(entity_id)
        if entity is None:
            return None
        
        return GraphNode(
            entity_id=entity.id,
            entity_type=entity.entity_type,
            attributes=entity.attributes,
            risk_score=entity.risk_score,
            metadata=entity.metadata,
        )
    
    def get_edge(self, source_id: str, target_id: str) -> Optional[GraphEdge]:
        """Get an edge by source and target IDs.
        
        Args:
            source_id: Source entity ID
            target_id: Target entity ID
            
        Returns:
            The GraphEdge if found, None otherwise
        """
        rel = self._store.get_relationship(source_id, target_id)
        if rel is None:
            return None
        
        return GraphEdge(
            source_id=rel.source_id,
            target_id=rel.target_id,
            relationship_type=rel.relationship_type,
            confidence_score=rel.confidence_score,
            metadata=rel.metadata,
        )
    
    def get_neighbors(self, entity_id: str, relationship_type: Optional[RelationshipType] = None) -> List[GraphNode]:
        """Get all neighboring nodes of an entity.
        
        Args:
            entity_id: ID of the entity
            relationship_type: Optional filter by relationship type
            
        Returns:
            List of neighboring GraphNodes
        """
        connected_ids = self._store.get_connected_entities(entity_id, relationship_type)
        
        nodes = []
        for connected_id in connected_ids:
            entity = self._store.get_entity(connected_id)
            if entity:
                nodes.append(GraphNode(
                    entity_id=entity.id,
                    entity_type=entity.entity_type,
                    attributes=entity.attributes,
                    risk_score=entity.risk_score,
                    metadata=entity.metadata,
                ))
        
        return nodes
    
    def traverse_bfs(self, start_id: str, max_depth: int = 3, relationship_type: Optional[RelationshipType] = None) -> GraphQueryResult:
        """Traverse the graph using breadth-first search.
        
        Args:
            start_id: Starting entity ID
            max_depth: Maximum traversal depth
            relationship_type: Optional filter by relationship type
            
        Returns:
            GraphQueryResult with traversal results
        """
        return self._traverse(start_id, TraversalOrder.BREADTH_FIRST, max_depth, relationship_type)
    
    def traverse_dfs(self, start_id: str, max_depth: int = 3, relationship_type: Optional[RelationshipType] = None) -> GraphQueryResult:
        """Traverse the graph using depth-first search.
        
        Args:
            start_id: Starting entity ID
            max_depth: Maximum traversal depth
            relationship_type: Optional filter by relationship type
            
        Returns:
            GraphQueryResult with traversal results
        """
        return self._traverse(start_id, TraversalOrder.DEPTH_FIRST, max_depth, relationship_type)
    
    def _traverse(self, start_id: str, order: TraversalOrder, max_depth: int, relationship_type: Optional[RelationshipType]) -> GraphQueryResult:
        """Internal traversal implementation.
        
        Args:
            start_id: Starting entity ID
            order: Traversal order
            max_depth: Maximum traversal depth
            relationship_type: Optional filter by relationship type
            
        Returns:
            GraphQueryResult with traversal results
        """
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        path: List[str] = []
        visited: Set[str] = set()
        current_depth = 0
        
        if order == TraversalOrder.BREADTH_FIRST:
            queue = deque([(start_id, 0)])
            while queue:
                current_id, depth = queue.popleft()
                
                if current_id in visited or depth > max_depth:
                    continue
                
                visited.add(current_id)
                current_depth = max(current_depth, depth)
                path.append(current_id)
                
                entity = self._store.get_entity(current_id)
                if entity:
                    nodes.append(GraphNode(
                        entity_id=entity.id,
                        entity_type=entity.entity_type,
                        attributes=entity.attributes,
                        risk_score=entity.risk_score,
                        metadata=entity.metadata,
                    ))
                
                relationships = self._store.get_relationships_for_entity(current_id)
                for rel in relationships:
                    if relationship_type and rel.relationship_type != relationship_type:
                        continue
                    
                    edges.append(GraphEdge(
                        source_id=rel.source_id,
                        target_id=rel.target_id,
                        relationship_type=rel.relationship_type,
                        confidence_score=rel.confidence_score,
                        metadata=rel.metadata,
                    ))
                    
                    connected_id = rel.target_id if rel.source_id == current_id else rel.source_id
                    if connected_id not in visited:
                        queue.append((connected_id, depth + 1))
        else:  # DEPTH_FIRST
            stack = [(start_id, 0)]
            while stack:
                current_id, depth = stack.pop()
                
                if current_id in visited or depth > max_depth:
                    continue
                
                visited.add(current_id)
                current_depth = max(current_depth, depth)
                path.append(current_id)
                
                entity = self._store.get_entity(current_id)
                if entity:
                    nodes.append(GraphNode(
                        entity_id=entity.id,
                        entity_type=entity.entity_type,
                        attributes=entity.attributes,
                        risk_score=entity.risk_score,
                        metadata=entity.metadata,
                    ))
                
                relationships = self._store.get_relationships_for_entity(current_id)
                for rel in relationships:
                    if relationship_type and rel.relationship_type != relationship_type:
                        continue
                    
                    edges.append(GraphEdge(
                        source_id=rel.source_id,
                        target_id=rel.target_id,
                        relationship_type=rel.relationship_type,
                        confidence_score=rel.confidence_score,
                        metadata=rel.metadata,
                    ))
                    
                    connected_id = rel.target_id if rel.source_id == current_id else rel.source_id
                    if connected_id not in visited:
                        stack.append((connected_id, depth + 1))
        
        return GraphQueryResult(
            nodes=nodes,
            edges=edges,
            path=path,
            depth=current_depth,
            total_nodes=len(nodes),
            total_edges=len(edges),
        )
    
    def find_shortest_path(self, source_id: str, target_id: str, max_depth: int = 10) -> List[str]:
        """Find the shortest path between two entities.
        
        Args:
            source_id: Source entity ID
            target_id: Target entity ID
            max_depth: Maximum path length
            
        Returns:
            List of entity IDs forming the path, empty if no path found
        """
        if not self._use_networkx or self._nx_graph is None:
            # Fall back to BFS implementation
            return self._bfs_shortest_path(source_id, target_id, max_depth)
        
        try:
            self._sync_to_networkx()
            path = nx.shortest_path(self._nx_graph, source_id, target_id)
            return path
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []
    
    def _bfs_shortest_path(self, source_id: str, target_id: str, max_depth: int) -> List[str]:
        """BFS-based shortest path implementation.
        
        Args:
            source_id: Source entity ID
            target_id: Target entity ID
            max_depth: Maximum path length
            
        Returns:
            List of entity IDs forming the path, empty if no path found
        """
        visited = {source_id}
        queue = deque([(source_id, [source_id])])
        
        while queue:
            current_id, path = queue.popleft()
            
            if len(path) > max_depth:
                continue
            
            if current_id == target_id:
                return path
            
            relationships = self._store.get_relationships_for_entity(current_id)
            for rel in relationships:
                connected_id = rel.target_id if rel.source_id == current_id else rel.source_id
                
                if connected_id not in visited:
                    visited.add(connected_id)
                    queue.append((connected_id, path + [connected_id]))
        
        return []
    
    def find_all_paths(self, source_id: str, target_id: str, max_depth: int = 5) -> List[List[str]]:
        """Find all paths between two entities up to a maximum depth.
        
        Args:
            source_id: Source entity ID
            target_id: Target entity ID
            max_depth: Maximum path length
            
        Returns:
            List of paths, each path is a list of entity IDs
        """
        if not self._use_networkx or self._nx_graph is None:
            return self._dfs_all_paths(source_id, target_id, max_depth)
        
        try:
            self._sync_to_networkx()
            paths = list(nx.all_simple_paths(self._nx_graph, source_id, target_id, cutoff=max_depth))
            return paths
        except nx.NodeNotFound:
            return []
    
    def _dfs_all_paths(self, source_id: str, target_id: str, max_depth: int) -> List[List[str]]:
        """DFS-based all paths implementation.
        
        Args:
            source_id: Source entity ID
            target_id: Target entity ID
            max_depth: Maximum path length
            
        Returns:
            List of paths, each path is a list of entity IDs
        """
        paths = []
        
        def dfs(current_id: str, target_id: str, visited: Set[str], path: List[str], depth: int):
            if depth > max_depth:
                return
            
            if current_id == target_id:
                paths.append(path.copy())
                return
            
            relationships = self._store.get_relationships_for_entity(current_id)
            for rel in relationships:
                connected_id = rel.target_id if rel.source_id == current_id else rel.source_id
                
                if connected_id not in visited:
                    visited.add(connected_id)
                    path.append(connected_id)
                    dfs(connected_id, target_id, visited, path, depth + 1)
                    path.pop()
                    visited.remove(connected_id)
        
        visited = {source_id}
        dfs(source_id, target_id, visited, [source_id], 0)
        return paths
    
    def get_subgraph(self, entity_ids: List[str]) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Get a subgraph containing the specified entities.
        
        Args:
            entity_ids: List of entity IDs to include
            
        Returns:
            Tuple of (nodes, edges) in the subgraph
        """
        nodes = []
        edges = []
        
        for entity_id in entity_ids:
            entity = self._store.get_entity(entity_id)
            if entity:
                nodes.append(GraphNode(
                    entity_id=entity.id,
                    entity_type=entity.entity_type,
                    attributes=entity.attributes,
                    risk_score=entity.risk_score,
                    metadata=entity.metadata,
                ))
                
                # Get relationships involving this entity
                relationships = self._store.get_relationships_for_entity(entity_id)
                for rel in relationships:
                    other_id = rel.target_id if rel.source_id == entity_id else rel.source_id
                    if other_id in entity_ids:
                        edge = GraphEdge(
                            source_id=rel.source_id,
                            target_id=rel.target_id,
                            relationship_type=rel.relationship_type,
                            confidence_score=rel.confidence_score,
                            metadata=rel.metadata,
                        )
                        # Avoid duplicates
                        if edge not in edges:
                            edges.append(edge)
        
        return nodes, edges
    
    def get_graph_stats(self) -> Dict[str, Any]:
        """Get statistics about the knowledge graph.
        
        Returns:
            Dictionary of graph statistics
        """
        stats = self._store.get_stats()
        
        if self._use_networkx and self._nx_graph is not None:
            self._sync_to_networkx()
            stats["graph_density"] = nx.density(self._nx_graph) if len(self._nx_graph) > 0 else 0
            stats["graph_connected_components"] = nx.number_connected_components(self._nx_graph) if len(self._nx_graph) > 0 else 0
            
            if len(self._nx_graph) > 0:
                try:
                    stats["graph_diameter"] = nx.diameter(self._nx_graph.to_undirected())
                except nx.NetworkXError:
                    stats["graph_diameter"] = -1
            else:
                stats["graph_diameter"] = -1
        else:
            stats["graph_density"] = 0
            stats["graph_connected_components"] = 0
            stats["graph_diameter"] = -1
        
        return stats
    
    def clear(self) -> None:
        """Clear all graph data."""
        self._store.clear()
        
        if self._use_networkx and self._nx_graph is not None:
            with self._graph_lock:
                self._nx_graph.clear()
        
        logger.info("Knowledge graph cleared")


# Global singleton instance
_knowledge_graph: Optional[KnowledgeGraph] = None
_graph_lock = object()


def get_knowledge_graph(store: Optional[EntityStore] = None) -> KnowledgeGraph:
    """Get or create the singleton KnowledgeGraph instance.
    
    Args:
        store: Optional entity store
        
    Returns:
        The singleton KnowledgeGraph instance
    """
    global _knowledge_graph
    
    if _knowledge_graph is None:
        _knowledge_graph = KnowledgeGraph(store=store)
    return _knowledge_graph