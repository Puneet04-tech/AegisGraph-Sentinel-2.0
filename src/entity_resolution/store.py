"""
Thread-safe entity storage with LRU cache for Entity Resolution Engine.

Provides:
    EntityStore: Thread-safe storage for entities and relationships with O(1) lookup
    get_entity_store: Singleton getter for the entity store
"""

from collections import OrderedDict
from threading import Lock
from typing import Dict, List, Optional, Set, Tuple, Any
import logging

from .models import Entity, EntityRelationship, FraudCluster, EntityType, RelationshipType

logger = logging.getLogger(__name__)


class EntityStore:
    """Thread-safe entity storage with LRU cache for O(1) entity lookup.

    This store provides:
        - O(1) entity lookup by ID
        - O(1) entity lookup by type and value
        - LRU cache for bounded memory usage
        - Thread-safe operations with locks
        - Efficient relationship storage and querying

    Attributes:
        max_size: Maximum number of entities to store (LRU eviction threshold)
        max_relationships: Maximum number of relationships to store
    """

    def __init__(self, max_size: int = 10000, max_relationships: int = 50000):
        """Initialize the entity store.

        Args:
            max_size: Maximum number of entities to store
            max_relationships: Maximum number of relationships to store
        """
        self._max_size = max_size
        self._max_relationships = max_relationships

        # Entity storage with LRU cache
        self._entities: OrderedDict[str, Entity] = OrderedDict()
        self._entity_lock = Lock()

        # Relationship storage
        self._relationships: Dict[str, EntityRelationship] = {}
        self._relationship_lock = Lock()

        # Index structures for O(1) lookups
        self._entity_by_type_value: Dict[Tuple[EntityType, str], str] = {}  # (type, value) -> entity_id
        self._entity_by_type_value_lock = Lock()

        # Relationship index: source_id -> list of relationship IDs
        self._relationships_by_source: Dict[str, List[str]] = {}
        # Relationship index: target_id -> list of relationship IDs
        self._relationships_by_target: Dict[str, List[str]] = {}
        # Relationship index: (source_type, target_type, rel_type) -> list of relationship IDs
        self._relationships_by_type: Dict[Tuple[str, str, str], List[str]] = {}
        self._index_lock = Lock()

        # Cluster storage
        self._clusters: Dict[str, FraudCluster] = {}
        self._clusters_by_entity: Dict[str, str] = {}  # entity_id -> cluster_id
        self._cluster_lock = Lock()

        # Statistics
        self._stats = {
            "entities_stored": 0,
            "relationships_stored": 0,
            "clusters_stored": 0,
            "cache_evictions": 0,
            "lookups": 0,
        }
        self._stats_lock = Lock()

    def _update_stats(self, key: str, increment: int = 1) -> None:
        """Update statistics counter thread-safely.

        Args:
            key: Statistic key to update
            increment: Amount to increment by
        """
        with self._stats_lock:
            self._stats[key] = self._stats.get(key, 0) + increment

    def _evict_lru_entity(self) -> Optional[Entity]:
        """Evict the least recently used entity from the cache.

        Returns:
            The evicted entity or None if store is empty
        """
        if not self._entities:
            return None

        # Pop the first (oldest) item
        entity_id, entity = self._entities.popitem(last=False)

        # Update indices
        key = (entity.entity_type, entity.value)
        self._entity_by_type_value.pop(key, None)

        self._update_stats("cache_evictions")
        logger.debug(f"Evicted entity {entity_id} from LRU cache")

        return entity

    def store_entity(self, entity: Entity) -> Entity:
        """Store an entity in the store.

        If the entity already exists, it will be updated. If the store is full,
        the least recently used entity will be evicted.

        Args:
            entity: Entity to store

        Returns:
            The stored entity
        """
        with self._entity_lock:
            # Check if entity exists
            if entity.id in self._entities:
                # Update existing entity
                existing = self._entities[entity.id]
                old_key = (existing.entity_type, existing.value)

                self._entities[entity.id] = entity
                self._entities.move_to_end(entity.id)

                # Update type-value index if type or value changed
                new_key = (entity.entity_type, entity.value)
                if old_key != new_key:
                    self._entity_by_type_value.pop(old_key, None)
                    with self._entity_by_type_value_lock:
                        self._entity_by_type_value[new_key] = entity.id
            else:
                # Check if we need to evict
                while len(self._entities) >= self._max_size:
                    self._evict_lru_entity()

                # Store new entity
                self._entities[entity.id] = entity

                # Update type-value index
                with self._entity_by_type_value_lock:
                    key = (entity.entity_type, entity.value)
                    self._entity_by_type_value[key] = entity.id

        self._update_stats("entities_stored")
        logger.debug(f"Stored entity {entity.id} of type {entity.entity_type.value}")
        return entity

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        """Get an entity by ID with O(1) lookup.

        Args:
            entity_id: ID of the entity to retrieve

        Returns:
            The entity if found, None otherwise
        """
        self._update_stats("lookups")

        with self._entity_lock:
            entity = self._entities.get(entity_id)
            if entity:
                # Move to end (most recently used)
                self._entities.move_to_end(entity_id)
                return entity
        return None

    def get_entity_by_type_value(self, entity_type: EntityType, value: str) -> Optional[Entity]:
        """Get an entity by type and value with O(1) lookup.

        Args:
            entity_type: Type of the entity
            value: Value of the entity

        Returns:
            The entity if found, None otherwise
        """
        self._update_stats("lookups")

        with self._entity_by_type_value_lock:
            entity_id = self._entity_by_type_value.get((entity_type, value))

        if entity_id:
            return self.get_entity(entity_id)
        return None

    def delete_entity(self, entity_id: str) -> bool:
        """Delete an entity by ID.

        Args:
            entity_id: ID of the entity to delete

        Returns:
            True if deleted, False if not found
        """
        with self._entity_lock:
            entity = self._entities.pop(entity_id, None)
            if entity is None:
                return False

            # Update type-value index
            key = (entity.entity_type, entity.value)
            with self._entity_by_type_value_lock:
                self._entity_by_type_value.pop(key, None)

        # Remove from cluster if present
        with self._cluster_lock:
            cluster_id = self._clusters_by_entity.pop(entity_id, None)
            if cluster_id and cluster_id in self._clusters:
                self._clusters[cluster_id].remove_entity(entity_id)

        # Remove relationships involving this entity
        self._remove_relationships_for_entity(entity_id)

        logger.debug(f"Deleted entity {entity_id}")
        return True

    def _remove_relationships_for_entity(self, entity_id: str) -> None:
        """Remove all relationships involving an entity.

        Args:
            entity_id: ID of the entity
        """
        with self._relationship_lock:
            # Find relationships to remove
            to_remove = []
            for rel_id, rel in self._relationships.items():
                if rel.source_id == entity_id or rel.target_id == entity_id:
                    to_remove.append(rel_id)

            for rel_id in to_remove:
                self._relationships.pop(rel_id, None)

        with self._index_lock:
            self._relationships_by_source.pop(entity_id, None)
            self._relationships_by_target.pop(entity_id, None)

        self._update_stats("relationships_stored", -len(to_remove))

    def store_relationship(self, relationship: EntityRelationship) -> EntityRelationship:
        """Store a relationship between two entities.

        Args:
            relationship: Relationship to store

        Returns:
            The stored relationship
        """
        rel_id = f"{relationship.source_id}:{relationship.target_id}:{relationship.relationship_type.value}"

        with self._relationship_lock:
            # Check if we need to evict old relationships
            while len(self._relationships) >= self._max_relationships:
                # Remove oldest relationship
                if self._relationships:
                    oldest_id = next(iter(self._relationships))
                    rel = self._relationships.pop(oldest_id)
                    self._update_stats("relationships_stored", -1)

                    # Update indices
                    with self._index_lock:
                        for idx in [self._relationships_by_source, self._relationships_by_target]:
                            for key, rel_list in list(idx.items()):
                                if oldest_id in rel_list:
                                    rel_list.remove(oldest_id)

                    type_key = (rel.source_id[:8], rel.target_id[:8], rel.relationship_type.value)
                    if type_key in self._relationships_by_type:
                        if oldest_id in self._relationships_by_type[type_key]:
                            self._relationships_by_type[type_key].remove(oldest_id)

            self._relationships[rel_id] = relationship

        # Update indices
        with self._index_lock:
            if relationship.source_id not in self._relationships_by_source:
                self._relationships_by_source[relationship.source_id] = []
            self._relationships_by_source[relationship.source_id].append(rel_id)

            if relationship.target_id not in self._relationships_by_target:
                self._relationships_by_target[relationship.target_id] = []
            self._relationships_by_target[relationship.target_id].append(rel_id)

            type_key = (relationship.source_id[:8], relationship.target_id[:8], relationship.relationship_type.value)
            if type_key not in self._relationships_by_type:
                self._relationships_by_type[type_key] = []
            self._relationships_by_type[type_key].append(rel_id)

        self._update_stats("relationships_stored")
        logger.debug(f"Stored relationship {rel_id}")
        return relationship

    def get_relationship(
        self, source_id: str, target_id: str, rel_type: Optional[RelationshipType] = None
    ) -> Optional[EntityRelationship]:
        """Get a relationship by source and target IDs.

        Args:
            source_id: Source entity ID
            target_id: Target entity ID
            rel_type: Optional relationship type filter

        Returns:
            The relationship if found, None otherwise
        """
        if rel_type:
            rel_id = f"{source_id}:{target_id}:{rel_type.value}"
            with self._relationship_lock:
                return self._relationships.get(rel_id)

        # Return first matching relationship
        with self._index_lock:
            rel_ids = self._relationships_by_source.get(source_id, [])

        with self._relationship_lock:
            for rel_id in rel_ids:
                rel = self._relationships.get(rel_id)
                if rel and rel.target_id == target_id:
                    return rel
        return None

    def get_relationships_for_entity(
        self, entity_id: str, as_source: bool = True, as_target: bool = True
    ) -> List[EntityRelationship]:
        """Get all relationships for an entity.

        Args:
            entity_id: ID of the entity
            as_source: Include relationships where entity is the source
            as_target: Include relationships where entity is the target

        Returns:
            List of relationships
        """
        rel_ids = set()

        with self._index_lock:
            if as_source:
                rel_ids.update(self._relationships_by_source.get(entity_id, []))
            if as_target:
                rel_ids.update(self._relationships_by_target.get(entity_id, []))

        with self._relationship_lock:
            return [self._relationships[rid] for rid in rel_ids if rid in self._relationships]

    def get_connected_entities(self, entity_id: str, relationship_type: Optional[RelationshipType] = None) -> List[str]:
        """Get all entity IDs connected to the given entity.

        Args:
            entity_id: ID of the entity
            relationship_type: Optional filter by relationship type

        Returns:
            List of connected entity IDs
        """
        relationships = self.get_relationships_for_entity(entity_id)

        connected = []
        for rel in relationships:
            if relationship_type and rel.relationship_type != relationship_type:
                continue
            if rel.source_id == entity_id:
                connected.append(rel.target_id)
            else:
                connected.append(rel.source_id)

        return list(set(connected))

    def store_cluster(self, cluster: FraudCluster) -> FraudCluster:
        """Store a fraud cluster.

        Args:
            cluster: Cluster to store

        Returns:
            The stored cluster
        """
        with self._cluster_lock:
            self._clusters[cluster.cluster_id] = cluster

            # Update entity-to-cluster mapping
            for entity_id in cluster.entity_ids:
                self._clusters_by_entity[entity_id] = cluster.cluster_id

        self._update_stats("clusters_stored")
        logger.debug(f"Stored cluster {cluster.cluster_id} with {len(cluster.entity_ids)} entities")
        return cluster

    def get_cluster(self, cluster_id: str) -> Optional[FraudCluster]:
        """Get a cluster by ID.

        Args:
            cluster_id: ID of the cluster

        Returns:
            The cluster if found, None otherwise
        """
        with self._cluster_lock:
            return self._clusters.get(cluster_id)

    def get_cluster_for_entity(self, entity_id: str) -> Optional[FraudCluster]:
        """Get the cluster containing an entity.

        Args:
            entity_id: ID of the entity

        Returns:
            The cluster if found, None otherwise
        """
        with self._cluster_lock:
            cluster_id = self._clusters_by_entity.get(entity_id)
            if cluster_id:
                return self._clusters.get(cluster_id)
        return None

    def get_all_clusters(self) -> List[FraudCluster]:
        """Get all stored clusters.

        Returns:
            List of all clusters
        """
        with self._cluster_lock:
            return list(self._clusters.values())

    def delete_cluster(self, cluster_id: str) -> bool:
        """Delete a cluster by ID.

        Args:
            cluster_id: ID of the cluster to delete

        Returns:
            True if deleted, False if not found
        """
        with self._cluster_lock:
            cluster = self._clusters.pop(cluster_id, None)
            if cluster is None:
                return False

            # Remove entity-to-cluster mappings
            for entity_id in cluster.entity_ids:
                self._clusters_by_entity.pop(entity_id, None)

        logger.debug(f"Deleted cluster {cluster_id}")
        return True

    def get_entities_by_type(self, entity_type: EntityType) -> List[Entity]:
        """Get all entities of a specific type.

        Args:
            entity_type: Type of entities to retrieve

        Returns:
            List of entities
        """
        result = []
        with self._entity_lock:
            for entity in self._entities.values():
                if entity.entity_type == entity_type:
                    result.append(entity)
        return result

    def get_entities_by_tag(self, tag: str) -> List[Entity]:
        """Get all entities with a specific tag.

        Args:
            tag: Tag to filter by

        Returns:
            List of entities
        """
        result = []
        with self._entity_lock:
            for entity in self._entities.values():
                if tag in entity.tags:
                    result.append(entity)
        return result

    def get_high_risk_entities(self, threshold: float = 0.7) -> List[Entity]:
        """Get all entities with risk score above threshold.

        Args:
            threshold: Minimum risk score (default 0.7)

        Returns:
            List of high-risk entities
        """
        result = []
        with self._entity_lock:
            for entity in self._entities.values():
                if entity.risk_score >= threshold:
                    result.append(entity)
        return sorted(result, key=lambda e: e.risk_score, reverse=True)

    def clear(self) -> None:
        """Clear all stored data."""
        with self._entity_lock:
            self._entities.clear()
        with self._entity_by_type_value_lock:
            self._entity_by_type_value.clear()
        with self._relationship_lock:
            self._relationships.clear()
        with self._index_lock:
            self._relationships_by_source.clear()
            self._relationships_by_target.clear()
            self._relationships_by_type.clear()
        with self._cluster_lock:
            self._clusters.clear()
            self._clusters_by_entity.clear()

        logger.info("Entity store cleared")

    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics.

        Returns:
            Dictionary of statistics
        """
        with self._stats_lock:
            stats = self._stats.copy()

        with self._entity_lock:
            stats["current_entities"] = len(self._entities)
        with self._relationship_lock:
            stats["current_relationships"] = len(self._relationships)
        with self._cluster_lock:
            stats["current_clusters"] = len(self._clusters)

        stats["cache_utilization"] = stats.get("current_entities", 0) / self._max_size if self._max_size > 0 else 0

        return stats


# Global singleton instance
_entity_store: Optional[EntityStore] = None
_store_lock = Lock()


def get_entity_store(max_size: int = 10000, max_relationships: int = 50000) -> EntityStore:
    """Get or create the singleton EntityStore instance.

    Args:
        max_size: Maximum number of entities to store
        max_relationships: Maximum number of relationships to store

    Returns:
        The singleton EntityStore instance
    """
    global _entity_store

    with _store_lock:
        if _entity_store is None:
            _entity_store = EntityStore(max_size=max_size, max_relationships=max_relationships)
        return _entity_store
