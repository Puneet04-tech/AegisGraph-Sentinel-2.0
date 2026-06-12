"""
Threat Supergraph Engine
Core engine for building and querying the planet-scale threat intelligence graph.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from .models import (
    ConfidenceLevel,
    EntityType,
    GraphAnalysis,
    GraphAnalysisType,
    GraphQuery,
    RelationshipType,
    SupergraphEdge,
    SupergraphNode,
)
from .store import SupergraphStore, get_supergraph_store


class ThreatSupergraphEngine:
    """Main engine for the threat supergraph."""
    
    def __init__(self, store: Optional[SupergraphStore] = None):
        self.store = store or get_supergraph_store()
        self._entity_cache: Dict[str, SupergraphNode] = {}
    
    def add_entity(
        self,
        entity_type: EntityType,
        name: str,
        properties: Optional[Dict[str, Any]] = None,
        threat_score: float = 0.0,
        risk_level: str = "UNKNOWN",
        tags: Optional[List[str]] = None,
    ) -> str:
        """Add an entity to the supergraph."""
        node_id = str(uuid4())
        node = SupergraphNode(
            node_id=node_id,
            entity_type=entity_type,
            name=name,
            properties=properties or {},
            threat_score=threat_score,
            risk_level=risk_level,
            tags=tags or [],
        )
        self.store.add_node(node)
        self._entity_cache[node_id] = node
        return node_id
    
    def connect_entities(
        self,
        source_id: str,
        target_id: str,
        relationship: RelationshipType,
        confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN,
        weight: float = 1.0,
        evidence: Optional[List[str]] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Connect two entities in the supergraph."""
        edge_id = str(uuid4())
        edge = SupergraphEdge(
            edge_id=edge_id,
            source_id=source_id,
            target_id=target_id,
            relationship_type=relationship,
            confidence=confidence,
            weight=weight,
            evidence=evidence or [],
            properties=properties or {},
        )
        self.store.add_edge(edge)
        return edge_id
    
    def find_entity_path(
        self,
        source_id: str,
        target_id: str,
        max_hops: int = 5,
    ) -> List[List[str]]:
        """Find paths between two entities."""
        paths = []
        
        def dfs(current: str, target: str, visited: Set[str], path: List[str], depth: int):
            if depth > max_hops:
                return
            if current == target:
                paths.append(path.copy())
                return
            
            visited.add(current)
            neighbors = self.store.get_neighbors(current, max_hops=1)
            
            for neighbor in neighbors:
                if neighbor not in visited:
                    path.append(neighbor)
                    dfs(neighbor, target, visited, path, depth + 1)
                    path.pop()
            
            visited.discard(current)
        
        dfs(source_id, target_id, set(), [source_id], 0)
        return paths[:10]
    
    def get_entity_cluster(
        self,
        entity_id: str,
        depth: int = 2,
    ) -> List[SupergraphNode]:
        """Get all entities connected to a given entity."""
        neighbor_ids = self.store.get_neighbors(entity_id, max_hops=depth)
        cluster = [self.store.get_node(entity_id)]
        
        for nid in neighbor_ids:
            node = self.store.get_node(nid)
            if node:
                cluster.append(node)
        
        return [n for n in cluster if n]
    
    def analyze_threat_community(
        self,
        entity_ids: List[str],
    ) -> GraphAnalysis:
        """Analyze a community of related entities."""
        analysis_id = str(uuid4())
        
        community_nodes = []
        for eid in entity_ids:
            node = self.store.get_node(eid)
            if node:
                community_nodes.append(node)
        
        centrality_scores = {}
        for node in community_nodes:
            degree = len(self.store.get_neighbors(node.node_id, max_hops=1))
            centrality_scores[node.node_id] = degree / max(1, len(community_nodes))
        
        communities = self._detect_communities(entity_ids)
        
        anomalies = self._detect_anomalies(community_nodes)
        
        return GraphAnalysis(
            analysis_id=analysis_id,
            analysis_type=GraphAnalysisType.COMMUNITY_DETECTION,
            entities=entity_ids,
            communities=communities,
            centrality_scores=centrality_scores,
            anomalies=anomalies,
            confidence=0.85,
        )
    
    def _detect_communities(self, entity_ids: List[str]) -> List[List[str]]:
        """Detect communities using simple clustering."""
        visited = set()
        communities = []
        
        for eid in entity_ids:
            if eid in visited:
                continue
            
            community = []
            queue = [eid]
            
            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                
                visited.add(current)
                community.append(current)
                
                neighbors = self.store.get_neighbors(current, max_hops=1)
                for neighbor in neighbors:
                    if neighbor in entity_ids and neighbor not in visited:
                        queue.append(neighbor)
            
            if community:
                communities.append(community)
        
        return communities
    
    def _detect_anomalies(
        self,
        nodes: List[SupergraphNode],
    ) -> List[Dict[str, Any]]:
        """Detect anomalous entities."""
        anomalies = []
        
        avg_threat = sum(n.threat_score for n in nodes) / max(1, len(nodes))
        
        for node in nodes:
            if node.threat_score > avg_threat * 2:
                anomalies.append({
                    "entity_id": node.node_id,
                    "type": "HIGH_THREAT_SCORE",
                    "score": node.threat_score,
                    "description": f"Entity {node.name} has unusually high threat score",
                })
        
        return anomalies
    
    def get_risk_score(self, entity_id: str) -> float:
        """Calculate risk score for an entity."""
        node = self.store.get_node(entity_id)
        if not node:
            return 0.0
        
        neighbors = self.store.get_neighbors(entity_id, max_hops=1)
        neighbor_scores = []
        
        for nid in neighbors:
            neighbor = self.store.get_node(nid)
            if neighbor:
                neighbor_scores.append(neighbor.threat_score)
        
        influence_score = sum(neighbor_scores) / max(1, len(neighbor_scores))
        centrality_bonus = len(neighbors) * 0.05
        
        return min(1.0, node.threat_score + influence_score * 0.3 + centrality_bonus)


def get_supergraph_engine() -> ThreatSupergraphEngine:
    """Get the global supergraph engine instance."""
    global _supergraph_engine
    if _supergraph_engine is None:
        _supergraph_engine = ThreatSupergraphEngine()
    return _supergraph_engine


_supergraph_engine: Optional[ThreatSupergraphEngine] = None