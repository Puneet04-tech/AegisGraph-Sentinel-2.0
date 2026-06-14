"""
Threat Supergraph Store
Central storage for the planet-scale threat intelligence graph.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from .models import (
    AttackPath,
    CampaignIntelligence,
    EntityType,
    GraphAnalysis,
    GraphAnalysisType,
    GraphQuery,
    RelationshipType,
    SupergraphEdge,
    SupergraphNode,
)


class SupergraphStore:
    """Store for the threat supergraph."""
    
    def __init__(self):
        self.nodes: Dict[str, SupergraphNode] = {}
        self.edges: Dict[str, SupergraphEdge] = {}
        self.entity_index: Dict[EntityType, Set[str]] = {et: set() for et in EntityType}
        self.relationship_index: Dict[RelationshipType, Set[str]] = {rt: set() for rt in RelationshipType}
        self._adjacency: Dict[str, Set[str]] = {}
        self._reverse_adjacency: Dict[str, Set[str]] = {}
    
    def add_node(self, node: SupergraphNode) -> str:
        """Add a node to the supergraph."""
        self.nodes[node.node_id] = node
        self.entity_index[node.entity_type].add(node.node_id)
        if node.node_id not in self._adjacency:
            self._adjacency[node.node_id] = set()
        if node.node_id not in self._reverse_adjacency:
            self._reverse_adjacency[node.node_id] = set()
        return node.node_id
    
    def get_node(self, node_id: str) -> Optional[SupergraphNode]:
        """Get a node by ID."""
        return self.nodes.get(node_id)
    
    def add_edge(self, edge: SupergraphEdge) -> str:
        """Add an edge to the supergraph."""
        self.edges[edge.edge_id] = edge
        self.relationship_index[edge.relationship_type].add(edge.edge_id)
        
        if edge.source_id not in self._adjacency:
            self._adjacency[edge.source_id] = set()
        self._adjacency[edge.source_id].add(edge.target_id)
        
        if edge.target_id not in self._reverse_adjacency:
            self._reverse_adjacency[edge.target_id] = set()
        self._reverse_adjacency[edge.target_id].add(edge.source_id)
        
        return edge.edge_id
    
    def get_edge(self, edge_id: str) -> Optional[SupergraphEdge]:
        """Get an edge by ID."""
        return self.edges.get(edge_id)
    
    def get_neighbors(
        self,
        node_id: str,
        max_hops: int = 1,
        relationship_types: Optional[List[RelationshipType]] = None
    ) -> Set[str]:
        """Get neighboring nodes within N hops."""
        visited = set()
        current_level = {node_id}
        
        for _ in range(max_hops):
            next_level = set()
            for nid in current_level:
                if nid in visited:
                    continue
                visited.add(nid)
                
                neighbors = self._adjacency.get(nid, set())
                for neighbor in neighbors:
                    if neighbor not in visited:
                        if relationship_types:
                            edge_ids = self.relationship_index.get(relationship_types[0], set())
                            for eid in edge_ids:
                                edge = self.edges.get(eid)
                                if edge and edge.source_id == nid:
                                    next_level.add(neighbor)
                                    break
                        else:
                            next_level.add(neighbor)
                
                reverse_neighbors = self._reverse_adjacency.get(nid, set())
                for neighbor in reverse_neighbors:
                    if neighbor not in visited:
                        next_level.add(neighbor)
            
            current_level = next_level
        
        visited.discard(node_id)
        return visited
    
    def query(self, query: GraphQuery) -> Tuple[List[SupergraphNode], List[SupergraphEdge]]:
        """Query the supergraph."""
        result_nodes = []
        result_edges = []
        
        for node in self.nodes.values():
            if query.entity_types and node.entity_type not in query.entity_types:
                continue
            
            matches = True
            for key, value in query.property_filters.items():
                if node.properties.get(key) != value:
                    matches = False
                    break
            
            if matches:
                result_nodes.append(node)
        
        for edge in self.edges.values():
            if query.relationship_types and edge.relationship_type not in query.relationship_types:
                continue
            result_edges.append(edge)
        
        return result_nodes[:query.limit], result_edges[:query.limit]
    
    def get_graph_stats(self) -> Dict[str, Any]:
        """Get supergraph statistics."""
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "nodes_by_type": {
                et.value: len(self.entity_index[et])
                for et in EntityType
            },
            "edges_by_relationship": {
                rt.value: len(self.relationship_index[rt])
                for rt in RelationshipType
            },
            "avg_degree": (
                sum(len(n) for n in self._adjacency.values()) / max(1, len(self.nodes))
                if self.nodes else 0
            ),
            "connected_components": self._count_connected_components(),
        }
    
    def _count_connected_components(self) -> int:
        """Count connected components."""
        visited = set()
        components = 0
        
        for node_id in self.nodes:
            if node_id not in visited:
                self._dfs_connected(node_id, visited)
                components += 1
        
        return components
    
    def _dfs_connected(self, start: str, visited: Set[str]):
        """DFS to find connected nodes."""
        stack = [start]
        while stack:
            node_id = stack.pop()
            if node_id in visited:
                continue
            visited.add(node_id)
            for neighbor in self._adjacency.get(node_id, set()):
                if neighbor not in visited:
                    stack.append(neighbor)
            for neighbor in self._reverse_adjacency.get(node_id, set()):
                if neighbor not in visited:
                    stack.append(neighbor)


def get_supergraph_store() -> SupergraphStore:
    """Get the global supergraph store instance."""
    global _supergraph_store
    if _supergraph_store is None:
        _supergraph_store = SupergraphStore()
    return _supergraph_store


_supergraph_store: Optional[SupergraphStore] = None