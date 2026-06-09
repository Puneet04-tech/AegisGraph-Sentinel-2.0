"""
Fraud Ring Detection Engine using graph clustering algorithms.

Provides:
    ClusterEngine: Engine for detecting fraud rings using Connected Components, BFS, DFS
    get_cluster_engine: Singleton getter for the cluster engine
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
import logging
import uuid

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None

from .models import Entity, EntityRelationship, FraudCluster, EntityType, RelationshipType
from .store import EntityStore, get_entity_store
from .knowledge_graph import KnowledgeGraph, get_knowledge_graph

logger = logging.getLogger(__name__)


class ClusteringAlgorithm(str, Enum):
    """Available clustering algorithms for fraud ring detection."""
    CONNECTED_COMPONENTS = "CONNECTED_COMPONENTS"
    BREADTH_FIRST_SEARCH = "BREADTH_FIRST_SEARCH"
    DEPTH_FIRST_SEARCH = "DEPTH_FIRST_SEARCH"
    LABEL_PROPAGATION = "LABEL_PROPAGATION"


@dataclass
class ClusterResult:
    """Result of a clustering operation."""
    clusters: List[FraudCluster]
    total_entities: int
    total_clusters: int
    high_risk_clusters: int
    algorithm_used: ClusteringAlgorithm
    processing_time_ms: float


@dataclass
class RingDetectionRequest:
    """Request for fraud ring detection."""
    min_cluster_size: int = 2
    min_confidence: float = 0.5
    entity_types: Optional[List[EntityType]] = None
    relationship_types: Optional[List[RelationshipType]] = None
    algorithm: ClusteringAlgorithm = ClusteringAlgorithm.CONNECTED_COMPONENTS
    risk_threshold: float = 0.6


class ClusterEngine:
    """Fraud Ring Detection Engine using graph clustering algorithms.
    
    This engine provides:
    - Connected Components algorithm for finding fraud rings
    - BFS-based clustering for network traversal
    - DFS-based clustering for deep path analysis
    - Label Propagation for community detection
    - Risk-based cluster scoring
    
    Attributes:
        store: Entity store for persistence
        knowledge_graph: Knowledge graph for traversal
        min_cluster_size: Minimum entities required to form a cluster
    """
    
    def __init__(self, store: Optional[EntityStore] = None, knowledge_graph: Optional[KnowledgeGraph] = None):
        """Initialize the cluster engine.
        
        Args:
            store: Optional entity store (creates singleton if not provided)
            knowledge_graph: Optional knowledge graph
        """
        self._store = store or get_entity_store()
        self._graph = knowledge_graph or get_knowledge_graph(self._store)
        self._min_cluster_size = 2
        
        logger.info("ClusterEngine initialized")
    
    def _build_graph(self, relationship_type: Optional[RelationshipType] = None) -> Any:
        """Build a NetworkX graph from stored relationships.
        
        Args:
            relationship_type: Optional filter by relationship type
            
        Returns:
            NetworkX graph
        """
        if not NETWORKX_AVAILABLE:
            return None
        
        G = nx.Graph()
        
        # Add all entities as nodes
        with self._store._entity_lock:
            for entity_id, entity in self._store._entities.items():
                G.add_node(entity_id, entity_type=entity.entity_type.value, risk_score=entity.risk_score)
        
        # Add edges for relationships
        with self._store._relationship_lock:
            for rel_id, rel in self._store._relationships.items():
                if relationship_type and rel.relationship_type != relationship_type:
                    continue
                
                if rel.confidence_score >= 0.5:  # Only include high-confidence relationships
                    G.add_edge(
                        rel.source_id,
                        rel.target_id,
                        relationship_type=rel.relationship_type.value,
                        confidence_score=rel.confidence_score,
                    )
        
        return G
    
    def _calculate_cluster_risk_score(self, entity_ids: List[str]) -> float:
        """Calculate the aggregate risk score for a cluster.
        
        Args:
            entity_ids: List of entity IDs in the cluster
            
        Returns:
            Aggregate risk score (0.0 to 1.0)
        """
        if not entity_ids:
            return 0.0
        
        risk_scores = []
        for entity_id in entity_ids:
            entity = self._store.get_entity(entity_id)
            if entity:
                risk_scores.append(entity.risk_score)
        
        if not risk_scores:
            return 0.0
        
        # Use weighted average with emphasis on high-risk entities
        max_risk = max(risk_scores)
        avg_risk = sum(risk_scores) / len(risk_scores)
        
        # Combined score: 60% max, 40% average
        return min(max_risk * 0.6 + avg_risk * 0.4, 1.0)
    
    def detect_clusters_connected_components(self, min_size: int = 2, risk_threshold: float = 0.0) -> List[FraudCluster]:
        """Detect fraud clusters using Connected Components algorithm.
        
        Args:
            min_size: Minimum cluster size
            risk_threshold: Minimum cluster risk score to include
            
        Returns:
            List of detected FraudClusters
        """
        import time
        start_time = time.time()
        
        G = self._build_graph()
        if G is None or len(G.nodes) == 0:
            return []
        
        # Find connected components
        components = list(nx.connected_components(G))
        
        clusters = []
        for component in components:
            if len(component) < min_size:
                continue
            
            entity_ids = list(component)
            risk_score = self._calculate_cluster_risk_score(entity_ids)
            
            if risk_score < risk_threshold:
                continue
            
            cluster = FraudCluster(
                entity_ids=set(entity_ids),
                risk_score=risk_score,
                tags={"connected_component", "fraud_ring"},
                metadata={
                    "algorithm": "CONNECTED_COMPONENTS",
                    "size": len(entity_ids),
                },
            )
            
            self._store.store_cluster(cluster)
            clusters.append(cluster)
        
        processing_time = (time.time() - start_time) * 1000
        logger.info(f"Connected Components: Found {len(clusters)} clusters in {processing_time:.2f}ms")
        
        return clusters
    
    def detect_clusters_bfs(self, start_entity_id: Optional[str] = None, min_size: int = 2, max_depth: int = 3) -> List[FraudCluster]:
        """Detect fraud clusters using BFS-based traversal.
        
        Args:
            start_entity_id: Optional starting entity for traversal
            min_size: Minimum cluster size
            max_depth: Maximum traversal depth
            
        Returns:
            List of detected FraudClusters
        """
        import time
        start_time = time.time()
        
        visited: Set[str] = set()
        clusters: List[FraudCluster] = []
        
        # Get all entity IDs if no start entity specified
        if start_entity_id is None:
            with self._store._entity_lock:
                entity_ids = list(self._store._entities.keys())
        else:
            entity_ids = [start_entity_id]
        
        for start_id in entity_ids:
            if start_id in visited:
                continue
            
            # BFS traversal to find connected component
            component = set()
            queue = [start_id]
            
            while queue:
                current_id = queue.pop(0)
                
                if current_id in visited:
                    continue
                
                visited.add(current_id)
                component.add(current_id)
                
                # Get connected entities
                relationships = self._store.get_relationships_for_entity(current_id)
                
                for rel in relationships:
                    if rel.confidence_score < 0.5:
                        continue
                    
                    connected_id = rel.target_id if rel.source_id == current_id else rel.source_id
                    
                    if connected_id not in visited and len(component) < 100:  # Limit cluster size
                        queue.append(connected_id)
                
                # Stop if we've exceeded max depth from start
                if len(component) > max_depth * 10:
                    break
            
            if len(component) >= min_size:
                risk_score = self._calculate_cluster_risk_score(list(component))
                
                cluster = FraudCluster(
                    entity_ids=component,
                    risk_score=risk_score,
                    tags={"bfs_detected", "fraud_ring"},
                    metadata={
                        "algorithm": "BREADTH_FIRST_SEARCH",
                        "size": len(component),
                        "start_entity": start_id,
                    },
                )
                
                self._store.store_cluster(cluster)
                clusters.append(cluster)
        
        processing_time = (time.time() - start_time) * 1000
        logger.info(f"BFS Detection: Found {len(clusters)} clusters in {processing_time:.2f}ms")
        
        return clusters
    
    def detect_clusters_dfs(self, start_entity_id: Optional[str] = None, min_size: int = 2, max_depth: int = 5) -> List[FraudCluster]:
        """Detect fraud clusters using DFS-based traversal.
        
        Args:
            start_entity_id: Optional starting entity for traversal
            min_size: Minimum cluster size
            max_depth: Maximum traversal depth
            
        Returns:
            List of detected FraudClusters
        """
        import time
        start_time = time.time()
        
        visited: Set[str] = set()
        clusters: List[FraudCluster] = []
        
        # Get all entity IDs if no start entity specified
        if start_entity_id is None:
            with self._store._entity_lock:
                entity_ids = list(self._store._entities.keys())
        else:
            entity_ids = [start_entity_id]
        
        def dfs_collect(start: str, current_depth: int, component: Set[str]) -> Set[str]:
            """DFS helper to collect connected entities."""
            if current_depth > max_depth or start in visited:
                return component
            
            visited.add(start)
            component.add(start)
            
            relationships = self._store.get_relationships_for_entity(start)
            
            for rel in relationships:
                if rel.confidence_score < 0.5:
                    continue
                
                connected_id = rel.target_id if rel.source_id == start else rel.source_id
                
                if connected_id not in visited and len(component) < 50:  # Limit cluster size
                    dfs_collect(connected_id, current_depth + 1, component)
            
            return component
        
        for start_id in entity_ids:
            if start_id in visited:
                continue
            
            component = dfs_collect(start_id, 0, set())
            
            if len(component) >= min_size:
                risk_score = self._calculate_cluster_risk_score(list(component))
                
                cluster = FraudCluster(
                    entity_ids=component,
                    risk_score=risk_score,
                    tags={"dfs_detected", "fraud_ring"},
                    metadata={
                        "algorithm": "DEPTH_FIRST_SEARCH",
                        "size": len(component),
                        "start_entity": start_id,
                    },
                )
                
                self._store.store_cluster(cluster)
                clusters.append(cluster)
        
        processing_time = (time.time() - start_time) * 1000
        logger.info(f"DFS Detection: Found {len(clusters)} clusters in {processing_time:.2f}ms")
        
        return clusters
    
    def detect_clusters_label_propagation(self, min_size: int = 2) -> List[FraudCluster]:
        """Detect fraud clusters using Label Propagation algorithm.
        
        Args:
            min_size: Minimum cluster size
            
        Returns:
            List of detected FraudClusters
        """
        if not NETWORKX_AVAILABLE:
            logger.warning("Label Propagation requires NetworkX")
            return []
        
        import time
        start_time = time.time()
        
        G = self._build_graph()
        if G is None or len(G.nodes) == 0:
            return []
        
        try:
            # Run label propagation
            from networkx.algorithms.community import label_propagation_communities
            communities = list(label_propagation_communities(G))
        except Exception as e:
            logger.warning(f"Label propagation failed: {e}")
            return []
        
        clusters = []
        for community in communities:
            entity_ids = list(community)
            
            if len(entity_ids) < min_size:
                continue
            
            risk_score = self._calculate_cluster_risk_score(entity_ids)
            
            cluster = FraudCluster(
                entity_ids=set(entity_ids),
                risk_score=risk_score,
                tags={"label_propagation", "fraud_ring", "community"},
                metadata={
                    "algorithm": "LABEL_PROPAGATION",
                    "size": len(entity_ids),
                },
            )
            
            self._store.store_cluster(cluster)
            clusters.append(cluster)
        
        processing_time = (time.time() - start_time) * 1000
        logger.info(f"Label Propagation: Found {len(clusters)} clusters in {processing_time:.2f}ms")
        
        return clusters
    
    def detect_fraud_rings(self, request: RingDetectionRequest) -> ClusterResult:
        """Detect fraud rings using the specified algorithm.
        
        Args:
            request: Ring detection request parameters
            
        Returns:
            ClusterResult with detected clusters
        """
        import time
        start_time = time.time()
        
        clusters: List[FraudCluster] = []
        
        # Filter relationships if specified
        rel_type = request.relationship_types[0] if request.relationship_types else None
        
        if request.algorithm == ClusteringAlgorithm.CONNECTED_COMPONENTS:
            clusters = self.detect_clusters_connected_components(
                min_size=request.min_cluster_size,
                risk_threshold=request.risk_threshold,
            )
        elif request.algorithm == ClusteringAlgorithm.BREADTH_FIRST_SEARCH:
            clusters = self.detect_clusters_bfs(
                min_size=request.min_cluster_size,
                max_depth=5,
            )
        elif request.algorithm == ClusteringAlgorithm.DEPTH_FIRST_SEARCH:
            clusters = self.detect_clusters_dfs(
                min_size=request.min_cluster_size,
                max_depth=5,
            )
        elif request.algorithm == ClusteringAlgorithm.LABEL_PROPAGATION:
            clusters = self.detect_clusters_label_propagation(
                min_size=request.min_cluster_size,
            )
        
        # Filter by entity types if specified
        if request.entity_types:
            filtered_clusters = []
            for cluster in clusters:
                valid_entities = []
                for entity_id in cluster.entity_ids:
                    entity = self._store.get_entity(entity_id)
                    if entity and entity.entity_type in request.entity_types:
                        valid_entities.append(entity_id)
                
                if len(valid_entities) >= request.min_cluster_size:
                    cluster.entity_ids = set(valid_entities)
                    filtered_clusters.append(cluster)
            clusters = filtered_clusters
        
        # Count high-risk clusters
        high_risk_clusters = sum(1 for c in clusters if c.risk_score >= request.risk_threshold)
        
        # Calculate total entities
        total_entities = sum(len(c.entity_ids) for c in clusters)
        
        processing_time = (time.time() - start_time) * 1000
        
        return ClusterResult(
            clusters=clusters,
            total_entities=total_entities,
            total_clusters=len(clusters),
            high_risk_clusters=high_risk_clusters,
            algorithm_used=request.algorithm,
            processing_time_ms=processing_time,
        )
    
    def get_high_risk_rings(self, threshold: float = 0.7) -> List[FraudCluster]:
        """Get all fraud rings with risk score above threshold.
        
        Args:
            threshold: Minimum risk score (default 0.7)
            
        Returns:
            List of high-risk FraudClusters sorted by risk score
        """
        all_clusters = self._store.get_all_clusters()
        high_risk = [c for c in all_clusters if c.risk_score >= threshold]
        return sorted(high_risk, key=lambda c: c.risk_score, reverse=True)
    
    def get_ring_members(self, cluster_id: str) -> List[Entity]:
        """Get all entities in a fraud ring.
        
        Args:
            cluster_id: ID of the cluster
            
        Returns:
            List of entities in the ring
        """
        cluster = self._store.get_cluster(cluster_id)
        if cluster is None:
            return []
        
        entities = []
        for entity_id in cluster.entity_ids:
            entity = self._store.get_entity(entity_id)
            if entity:
                entities.append(entity)
        
        return entities
    
    def get_ring_relationships(self, cluster_id: str) -> List[EntityRelationship]:
        """Get all relationships within a fraud ring.
        
        Args:
            cluster_id: ID of the cluster
            
        Returns:
            List of relationships within the ring
        """
        cluster = self._store.get_cluster(cluster_id)
        if cluster is None:
            return []
        
        relationships = []
        for entity_id in cluster.entity_ids:
            rels = self._store.get_relationships_for_entity(entity_id)
            for rel in rels:
                # Only include if both entities are in the cluster
                if rel.source_id in cluster.entity_ids and rel.target_id in cluster.entity_ids:
                    if rel not in relationships:
                        relationships.append(rel)
        
        return relationships
    
    def merge_clusters(self, cluster_ids: List[str]) -> Optional[FraudCluster]:
        """Merge multiple clusters into one.
        
        Args:
            cluster_ids: List of cluster IDs to merge
            
        Returns:
            The merged FraudCluster or None if not all clusters found
        """
        clusters = []
        for cluster_id in cluster_ids:
            cluster = self._store.get_cluster(cluster_id)
            if cluster is None:
                return None
            clusters.append(cluster)
        
        # Merge entity IDs
        merged_entity_ids = set()
        for cluster in clusters:
            merged_entity_ids.update(cluster.entity_ids)
        
        # Calculate new risk score
        risk_score = self._calculate_cluster_risk_score(list(merged_entity_ids))
        
        # Create new merged cluster
        merged_cluster = FraudCluster(
            entity_ids=merged_entity_ids,
            risk_score=risk_score,
            tags={"merged", "fraud_ring"},
            metadata={
                "source_clusters": cluster_ids,
                "original_count": len(cluster_ids),
            },
        )
        
        # Delete original clusters
        for cluster_id in cluster_ids:
            self._store.delete_cluster(cluster_id)
        
        # Store merged cluster
        self._store.store_cluster(merged_cluster)
        
        logger.info(f"Merged {len(cluster_ids)} clusters into {merged_cluster.cluster_id}")
        return merged_cluster
    
    def split_cluster(self, cluster_id: str, entity_ids: List[str]) -> Tuple[Optional[FraudCluster], Optional[FraudCluster]]:
        """Split a cluster into two by removing specified entities.
        
        Args:
            cluster_id: ID of the cluster to split
            entity_ids: Entity IDs to remove from the cluster
            
        Returns:
            Tuple of (remaining_cluster, removed_cluster)
        """
        cluster = self._store.get_cluster(cluster_id)
        if cluster is None:
            return None, None
        
        removed_set = set(entity_ids)
        remaining_set = cluster.entity_ids - removed_set
        
        if len(remaining_set) < 2:
            # Can't form a valid cluster with remaining entities
            return None, None
        
        # Create remaining cluster
        remaining_risk = self._calculate_cluster_risk_score(list(remaining_set))
        remaining_cluster = FraudCluster(
            entity_ids=remaining_set,
            risk_score=remaining_risk,
            tags={"split_remaining", "fraud_ring"},
            metadata={"source_cluster": cluster_id},
        )
        
        # Create removed cluster
        removed_risk = self._calculate_cluster_risk_score(list(removed_set))
        removed_cluster = FraudCluster(
            entity_ids=removed_set,
            risk_score=removed_risk,
            tags={"split_removed", "fraud_ring"},
            metadata={"source_cluster": cluster_id},
        )
        
        # Delete original and store new clusters
        self._store.delete_cluster(cluster_id)
        self._store.store_cluster(remaining_cluster)
        self._store.store_cluster(removed_cluster)
        
        logger.info(f"Split cluster {cluster_id} into two clusters")
        return remaining_cluster, removed_cluster
    
    def update_cluster_risk_scores(self) -> int:
        """Update risk scores for all clusters based on entity risk scores.
        
        Returns:
            Number of clusters updated
        """
        clusters = self._store.get_all_clusters()
        updated = 0
        
        for cluster in clusters:
            new_risk = self._calculate_cluster_risk_score(list(cluster.entity_ids))
            if abs(new_risk - cluster.risk_score) > 0.01:
                cluster.update_risk_score(new_risk)
                self._store.store_cluster(cluster)
                updated += 1
        
        logger.info(f"Updated {updated} cluster risk scores")
        return updated


# Global singleton instance
_cluster_engine: Optional[ClusterEngine] = None
_cluster_lock = object()


def get_cluster_engine(store: Optional[EntityStore] = None) -> ClusterEngine:
    """Get or create the singleton ClusterEngine instance.
    
    Args:
        store: Optional entity store
        
    Returns:
        The singleton ClusterEngine instance
    """
    global _cluster_engine
    
    if _cluster_engine is None:
        _cluster_engine = ClusterEngine(store=store)
    return _cluster_engine