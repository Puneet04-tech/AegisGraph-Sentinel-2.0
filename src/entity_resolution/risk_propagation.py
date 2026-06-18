"""
Risk Propagation Engine for propagating risk scores across connected entities.

Provides:
    RiskPropagator: Engine for propagating risk scores through the knowledge graph
    get_risk_propagator: Singleton getter for the risk propagator

Example:
    high_risk_account (0.95) -> shared_device (0.75) -> connected_accounts (0.60)
"""

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple, Any
import logging

from .models import Entity, EntityRelationship, EntityType, RelationshipType
from .store import EntityStore, get_entity_store
from .knowledge_graph import KnowledgeGraph, get_knowledge_graph

logger = logging.getLogger(__name__)


@dataclass
class PropagationConfig:
    """Configuration for risk propagation."""

    decay_factor: float = 0.85  # Risk decays by this factor per hop
    min_confidence_threshold: float = 0.3  # Minimum confidence to propagate through
    max_propagation_depth: int = 5  # Maximum propagation depth
    risk_threshold: float = 0.1  # Minimum risk to consider
    propagation_weights: Dict[RelationshipType, float] = None  # Custom weights per relationship type

    def __post_init__(self):
        if self.propagation_weights is None:
            self.propagation_weights = {
                RelationshipType.SHARED_DEVICE: 0.90,
                RelationshipType.SHARED_IP: 0.80,
                RelationshipType.SHARED_PHONE: 0.85,
                RelationshipType.SHARED_EMAIL: 0.75,
                RelationshipType.WALLET_OWNER: 0.95,
                RelationshipType.WALLET_BENEFICIARY: 0.90,
                RelationshipType.TRANSFER_FROM: 0.85,
                RelationshipType.TRANSFER_TO: 0.85,
                RelationshipType.SAME_PERSON: 1.0,
                RelationshipType.FAMILY_MEMBER: 0.80,
                RelationshipType.BUSINESS_ASSOCIATE: 0.70,
                RelationshipType.CASH_OUT: 0.90,
                RelationshipType.MULE_ACCOUNT: 1.0,
            }


@dataclass
class PropagationResult:
    """Result of risk propagation."""

    source_entity_id: str
    original_risk_score: float
    propagated_entities: Dict[str, float]  # entity_id -> propagated risk
    total_propagated: int
    max_propagation_depth: int
    processing_time_ms: float


class RiskPropagator:
    """Risk Propagation Engine for spreading risk scores through the knowledge graph.

    This engine propagates risk from high-risk entities to connected entities,
    with configurable decay and confidence thresholds.

    Attributes:
        store: Entity store for persistence
        knowledge_graph: Knowledge graph for traversal
        config: Propagation configuration
    """

    def __init__(
        self,
        store: Optional[EntityStore] = None,
        knowledge_graph: Optional[KnowledgeGraph] = None,
        config: Optional[PropagationConfig] = None,
    ):
        """Initialize the risk propagator.

        Args:
            store: Optional entity store (creates singleton if not provided)
            knowledge_graph: Optional knowledge graph
            config: Optional propagation configuration
        """
        self._store = store or get_entity_store()
        self._graph = knowledge_graph or get_knowledge_graph(self._store)
        self._config = config or PropagationConfig()

        logger.info("RiskPropagator initialized with decay_factor={}".format(self._config.decay_factor))

    def propagate_risk(self, source_entity_id: str, additional_risk: float = 0.0) -> PropagationResult:
        """Propagate risk from a source entity to all connected entities.

        Args:
            source_entity_id: ID of the source entity
            additional_risk: Additional risk to add (e.g., from a new transaction)

        Returns:
            PropagationResult with all affected entities
        """
        import time

        start_time = time.time()

        source_entity = self._store.get_entity(source_entity_id)
        if source_entity is None:
            return PropagationResult(
                source_entity_id=source_entity_id,
                original_risk_score=0.0,
                propagated_entities={},
                total_propagated=0,
                max_propagation_depth=0,
                processing_time_ms=0.0,
            )

        base_risk = source_entity.risk_score + additional_risk
        propagated: Dict[str, float] = {}
        visited: Set[str] = {source_entity_id}
        current_depth = 0

        # Queue for BFS propagation: (entity_id, current_risk, depth)
        # Queue for BFS propagation: (entity_id, current_risk, depth)
        queue: deque[Tuple[str, float, int]] = deque([(source_entity_id, base_risk, 0)])

        while queue:
            current_id, current_risk, depth = queue.popleft()

            if depth > self._config.max_propagation_depth:
                continue

            if current_risk < self._config.risk_threshold:
                continue

            current_depth = max(current_depth, depth)

            # Get relationships for this entity
            relationships = self._store.get_relationships_for_entity(current_id)

            for rel in relationships:
                # Check confidence threshold
                if rel.confidence_score < self._config.min_confidence_threshold:
                    continue

                # Get connected entity
                connected_id = rel.target_id if rel.source_id == current_id else rel.source_id

                if connected_id in visited:
                    continue

                visited.add(connected_id)

                # Get relationship type weight
                rel_weight = self._config.propagation_weights.get(rel.relationship_type, 0.5)

                # Calculate propagated risk
                propagated_risk = current_risk * self._config.decay_factor * rel_weight

                # Apply confidence modifier
                propagated_risk *= rel.confidence_score

                if propagated_risk >= self._config.risk_threshold:
                    propagated[connected_id] = propagated_risk

                    # Update the entity's risk score (additive)
                    connected_entity = self._store.get_entity(connected_id)
                    if connected_entity:
                        new_risk = min(connected_entity.risk_score + propagated_risk * 0.3, 1.0)
                        connected_entity.update_risk_score(new_risk)
                        self._store.store_entity(connected_entity)

                    # Add to queue for further propagation
                    queue.append((connected_id, propagated_risk, depth + 1))

        processing_time = (time.time() - start_time) * 1000

        result = PropagationResult(
            source_entity_id=source_entity_id,
            original_risk_score=base_risk,
            propagated_entities=propagated,
            total_propagated=len(propagated),
            max_propagation_depth=current_depth,
            processing_time_ms=processing_time,
        )

        logger.info(f"Propagated risk from {source_entity_id}: {len(propagated)} entities affected")
        return result

    def propagate_risk_bidirectional(self, entity_ids: List[str]) -> PropagationResult:
        """Propagate risk bidirectionally from multiple source entities.

        Args:
            entity_ids: List of source entity IDs

        Returns:
            Combined PropagationResult
        """
        import time

        start_time = time.time()

        all_propagated: Dict[str, float] = {}
        max_depth = 0

        for entity_id in entity_ids:
            result = self.propagate_risk(entity_id)
            max_depth = max(max_depth, result.max_propagation_depth)

            for prop_entity_id, prop_risk in result.propagated_entities.items():
                if prop_entity_id in all_propagated:
                    all_propagated[prop_entity_id] = max(all_propagated[prop_entity_id], prop_risk)
                else:
                    all_propagated[prop_entity_id] = prop_risk

        processing_time = (time.time() - start_time) * 1000

        return PropagationResult(
            source_entity_id=",".join(entity_ids[:3]) + ("..." if len(entity_ids) > 3 else ""),
            original_risk_score=0.0,
            propagated_entities=all_propagated,
            total_propagated=len(all_propagated),
            max_propagation_depth=max_depth,
            processing_time_ms=processing_time,
        )

    def calculate_contagion_score(self, entity_id: str) -> float:
        """Calculate the total contagion score for an entity.

        The contagion score represents how much risk the entity could spread
        to others if it were to become high-risk.

        Args:
            entity_id: ID of the entity

        Returns:
            Contagion score between 0.0 and 1.0
        """
        entity = self._store.get_entity(entity_id)
        if entity is None:
            return 0.0

        if entity.risk_score < 0.5:
            return 0.0

        # Count connections and their weights
        total_weight = 0.0
        connection_count = 0

        relationships = self._store.get_relationships_for_entity(entity_id)
        for rel in relationships:
            if rel.confidence_score >= self._config.min_confidence_threshold:
                rel_weight = self._config.propagation_weights.get(rel.relationship_type, 0.5)
                total_weight += rel_weight * rel.confidence_score
                connection_count += 1

        if connection_count == 0:
            return 0.0

        # Normalize: more connections = higher contagion potential
        avg_weight = total_weight / connection_count
        connection_factor = min(connection_count / 10.0, 1.0)  # Cap at 10 connections

        return min(avg_weight * connection_factor * entity.risk_score, 1.0)

    def get_risk_tier(self, risk_score: float) -> str:
        """Get the risk tier for a given risk score.

        Args:
            risk_score: Risk score between 0.0 and 1.0

        Returns:
            Risk tier string (CRITICAL, HIGH, MEDIUM, LOW)
        """
        if risk_score >= 0.8:
            return "CRITICAL"
        elif risk_score >= 0.6:
            return "HIGH"
        elif risk_score >= 0.3:
            return "MEDIUM"
        else:
            return "LOW"

    def get_contagion_report(self, entity_id: str, max_depth: int = 3) -> Dict[str, Any]:
        """Generate a detailed contagion report for an entity.

        Args:
            entity_id: ID of the entity
            max_depth: Maximum report depth

        Returns:
            Dictionary containing the contagion report
        """
        entity = self._store.get_entity(entity_id)
        if entity is None:
            return {"error": "Entity not found"}

        # Propagate risk to get all affected entities
        propagation = self.propagate_risk(entity_id)

        # Organize by tier
        critical = []
        high = []
        medium = []
        low = []

        for affected_id, risk in propagation.propagated_entities.items():
            tier = self.get_risk_tier(risk)
            affected_entity = self._store.get_entity(affected_id)

            entry = {
                "entity_id": affected_id,
                "entity_type": affected_entity.entity_type.value if affected_entity else "UNKNOWN",
                "propagated_risk": risk,
                "tier": tier,
            }

            if tier == "CRITICAL":
                critical.append(entry)
            elif tier == "HIGH":
                high.append(entry)
            elif tier == "MEDIUM":
                medium.append(entry)
            else:
                low.append(entry)

        # Sort each tier by risk
        critical.sort(key=lambda x: x["propagated_risk"], reverse=True)
        high.sort(key=lambda x: x["propagated_risk"], reverse=True)
        medium.sort(key=lambda x: x["propagated_risk"], reverse=True)
        low.sort(key=lambda x: x["propagated_risk"], reverse=True)

        return {
            "source_entity_id": entity_id,
            "source_entity_type": entity.entity_type.value,
            "source_risk_score": entity.risk_score,
            "source_contagion_score": self.calculate_contagion_score(entity_id),
            "total_affected": propagation.total_propagated,
            "max_depth": propagation.max_propagation_depth,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "processing_time_ms": propagation.processing_time_ms,
        }

    def batch_propagate(self, entity_ids: List[str], additional_risk: float = 0.0) -> List[PropagationResult]:
        """Propagate risk from multiple source entities.

        Args:
            entity_ids: List of source entity IDs
            additional_risk: Additional risk to add to each

        Returns:
            List of PropagationResults
        """
        results = []
        for entity_id in entity_ids:
            result = self.propagate_risk(entity_id, additional_risk)
            results.append(result)
        return results

    def update_entity_risk(self, entity_id: str, new_risk: float) -> bool:
        """Update an entity's risk score and propagate changes.

        Args:
            entity_id: ID of the entity
            new_risk: New risk score (0.0 to 1.0)

        Returns:
            True if updated, False if entity not found
        """
        entity = self._store.get_entity(entity_id)
        if entity is None:
            return False

        old_risk = entity.risk_score
        entity.update_risk_score(new_risk)
        self._store.store_entity(entity)

        # Propagate if risk increased significantly
        if new_risk > old_risk + 0.2:
            self.propagate_risk(entity_id, new_risk - old_risk)

        logger.info(f"Updated entity {entity_id} risk from {old_risk:.2f} to {new_risk:.2f}")
        return True

    def get_risk_propagation_path(self, source_id: str, target_id: str) -> List[Dict[str, Any]]:
        """Find the risk propagation path between two entities.

        Args:
            source_id: Source entity ID
            target_id: Target entity ID

        Returns:
            List of path segments with risk information
        """
        path = self._graph.find_shortest_path(source_id, target_id)

        if not path:
            return []

        segments = []
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]

            rel = self._store.get_relationship(source, target)
            if rel is None:
                rel = self._store.get_relationship(target, source)

            source_entity = self._store.get_entity(source)
            target_entity = self._store.get_entity(target)

            segment = {
                "from": source,
                "to": target,
                "relationship_type": rel.relationship_type.value if rel else "UNKNOWN",
                "confidence": rel.confidence_score if rel else 0.0,
                "from_risk": source_entity.risk_score if source_entity else 0.0,
                "to_risk": target_entity.risk_score if target_entity else 0.0,
            }

            segments.append(segment)

        return segments

    def set_config(self, config: PropagationConfig) -> None:
        """Update the propagation configuration.

        Args:
            config: New propagation configuration
        """
        self._config = config
        logger.info("Risk propagation config updated")

    def get_config(self) -> PropagationConfig:
        """Get the current propagation configuration.

        Returns:
            Current PropagationConfig
        """
        return self._config


# Global singleton instance
_risk_propagator: Optional[RiskPropagator] = None
_propagator_lock = object()


def get_risk_propagator(store: Optional[EntityStore] = None) -> RiskPropagator:
    """Get or create the singleton RiskPropagator instance.

    Args:
        store: Optional entity store

    Returns:
        The singleton RiskPropagator instance
    """
    global _risk_propagator

    if _risk_propagator is None:
        _risk_propagator = RiskPropagator(store=store)
    return _risk_propagator
