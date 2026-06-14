"""
Risk Propagation Engine for graph-based risk analysis.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from .models import (
    RiskPropagation,
    FederatedEntity,
    ThreatLevel,
    EntityType,
)
from .store import GlobalIntelligenceStore, get_global_intelligence_store
from .knowledge_graph import KnowledgeGraphEngine, get_knowledge_graph_engine


@dataclass
class PropagationPath:
    """Path of risk propagation."""
    path_id: str
    source_id: str
    target_id: str
    path: List[str]
    risk_score: float
    propagation_strength: float
    risk_factors: List[str]
    calculated_at: datetime


@dataclass
class PropagationConfig:
    """Configuration for risk propagation."""
    max_hops: int = 5
    min_propagation_strength: float = 0.1
    decay_factor: float = 0.7
    decay_per_hop: float = 0.2
    high_risk_threshold: float = 0.7


class RiskPropagationEngine:
    """
    Propagates risk through entity relationships.

    Handles:
    - Risk path discovery
    - Risk propagation calculation
    - Risk trajectory analysis
    - Risk mitigation recommendations
    """

    def __init__(
        self,
        store: Optional[GlobalIntelligenceStore] = None,
        graph_engine: Optional[KnowledgeGraphEngine] = None,
        config: Optional[PropagationConfig] = None,
    ):
        self._store = store or get_global_intelligence_store()
        self._graph = graph_engine or get_knowledge_graph_engine()
        self._config = config or PropagationConfig()
        self._propagation_cache: Dict[str, List[RiskPropagation]] = defaultdict(list)

    def propagate_risk(
        self,
        source_entity_id: str,
        max_hops: Optional[int] = None,
    ) -> List[RiskPropagation]:
        """Propagate risk from a source entity."""
        max_hops = max_hops or self._config.max_hops

        source = self._store.get_entity(source_entity_id)
        if not source:
            return []

        propagations: List[RiskPropagation] = []
        visited: Set[str] = {source_entity_id}
        queue = deque([(source_entity_id, source.risk_score, 1.0, [source_entity_id])])

        while queue:
            current_id, current_risk, strength, path = queue.popleft()

            if len(path) > max_hops:
                continue

            # Get connected entities
            edges = self._store.get_node_edges(current_id)
            for edge in edges:
                target_id = edge.target_id if edge.source_id == current_id else edge.source_id

                if target_id in visited:
                    continue

                # Calculate propagated risk
                hop_count = len(path)
                decay = self._config.decay_per_hop * (hop_count - 1)
                propagation_strength = strength * (1 - decay) * edge.weight
                propagated_risk = current_risk * propagation_strength

                if propagation_strength < self._config.min_propagation_strength:
                    continue

                visited.add(target_id)
                new_path = path + [target_id]

                # Create propagation record
                propagation = RiskPropagation(
                    propagation_id=str(uuid.uuid4()),
                    source_entity_id=source_entity_id,
                    target_entity_id=target_id,
                    propagation_path=new_path,
                    risk_score=propagated_risk,
                    propagation_strength=propagation_strength,
                    hop_count=hop_count,
                    risk_factors=self._identify_risk_factors(current_id, target_id, edge),
                    calculated_at=datetime.now(timezone.utc),
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
                )
                propagations.append(propagation)

                # Update entity risk score
                target = self._store.get_entity(target_id)
                if target:
                    target.risk_score = max(target.risk_score, propagated_risk)
                    self._store.store_entity(target)

                # Continue propagation
                queue.append((target_id, propagated_risk, propagation_strength, new_path))

        # Cache results
        self._propagation_cache[source_entity_id] = propagations

        return propagations

    def find_risk_paths(
        self,
        source_id: str,
        target_id: str,
        max_hops: int = 5,
    ) -> List[PropagationPath]:
        """Find all risk propagation paths between two entities."""
        paths: List[PropagationPath] = []

        # BFS to find all paths
        queue = deque([(source_id, source_id, [source_id], 1.0)])
        visited_paths: Set[Tuple[str, ...]] = set()

        while queue:
            current, original_source, path, strength = queue.popleft()

            if len(path) > max_hops:
                continue

            if current == target_id:
                # Found a path
                source = self._store.get_entity(original_source)
                source_risk = source.risk_score if source else 0.5

                propagation_path = PropagationPath(
                    path_id=str(uuid.uuid4()),
                    source_id=original_source,
                    target_id=target_id,
                    path=path,
                    risk_score=source_risk * strength,
                    propagation_strength=strength,
                    risk_factors=["path_found"],
                    calculated_at=datetime.now(timezone.utc),
                )
                paths.append(propagation_path)
                continue

            edges = self._store.get_node_edges(current)
            for edge in edges:
                next_node = edge.target_id if edge.source_id == current else edge.source_id

                if next_node in path:
                    continue

                path_key = tuple(sorted(path + [next_node]))
                if path_key in visited_paths:
                    continue
                visited_paths.add(path_key)

                new_strength = strength * edge.weight * (1 - self._config.decay_per_hop)
                queue.append((next_node, original_source, path + [next_node], new_strength))

        return paths

    def get_risk_trajectory(
        self,
        entity_id: str,
        time_horizon_hours: int = 24,
    ) -> Dict[str, Any]:
        """Get risk trajectory for an entity."""
        entity = self._store.get_entity(entity_id)
        if not entity:
            return {"error": "Entity not found"}

        # Current risk
        current_risk = entity.risk_score

        # Get propagation results
        propagations = self._propagation_cache.get(entity_id, [])
        affected_entities = [p.target_entity_id for p in propagations]

        # Calculate risk statistics
        if propagations:
            risk_scores = [p.risk_score for p in propagations]
            avg_propagated = sum(risk_scores) / len(risk_scores)
            max_propagated = max(risk_scores)
        else:
            avg_propagated = 0
            max_propagated = 0

        # Estimate trajectory
        trajectory = {
            "current_risk": current_risk,
            "risk_trend": self._calculate_trend(propagations),
            "affected_entities_count": len(set(affected_entities)),
            "avg_propagated_risk": avg_propagated,
            "max_propagated_risk": max_propagated,
            "threat_level": entity.threat_level.value,
            "recommendations": self._generate_risk_recommendations(entity, propagations),
        }

        return trajectory

    def identify_risk_clusters(
        self,
        min_size: int = 3,
    ) -> List[List[str]]:
        """Identify clusters of high-risk connected entities."""
        # Find connected components with high average risk
        components = self._graph.find_connected_components()
        risk_clusters: List[List[str]] = []

        for component in components:
            if len(component) < min_size:
                continue

            # Calculate average risk
            total_risk = 0.0
            high_risk_count = 0

            for entity_id in component:
                entity = self._store.get_entity(entity_id)
                if entity:
                    total_risk += entity.risk_score
                    if entity.risk_score >= self._config.high_risk_threshold:
                        high_risk_count += 1

            avg_risk = total_risk / len(component)

            # Cluster if high average risk or significant high-risk nodes
            if avg_risk >= 0.5 or high_risk_count >= min_size:
                risk_clusters.append(component)

        return risk_clusters

    def get_at_risk_entities(
        self,
        threshold: float = 0.5,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get entities at risk due to propagation."""
        at_risk: List[Dict[str, Any]] = []

        for entity in self._store._entities.values():
            # Check if entity has elevated risk
            if entity.risk_score >= threshold:
                # Get propagation paths
                paths = self.find_risk_paths(entity.entity_id, entity.entity_id, max_hops=3)

                at_risk.append({
                    "entity_id": entity.entity_id,
                    "entity_type": entity.entity_type.value,
                    "risk_score": entity.risk_score,
                    "threat_level": entity.threat_level.value,
                    "propagation_count": len(paths),
                    "partner_id": entity.partner_id,
                })

        # Sort by risk score
        at_risk.sort(key=lambda x: x["risk_score"], reverse=True)

        return at_risk[:limit]

    def _identify_risk_factors(
        self,
        source_id: str,
        target_id: str,
        edge: Any,
    ) -> List[str]:
        """Identify risk factors for propagation."""
        factors = []

        source = self._store.get_entity(source_id)
        target = self._store.get_entity(target_id)

        if source and target:
            # Same entity type increases risk
            if source.entity_type == target.entity_type:
                factors.append("same_entity_type")

            # Both high risk
            if (source.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL) and
                target.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)):
                factors.append("both_high_risk")

        # Relationship type
        factors.append(f"relationship:{edge.relationship_type}")

        # Edge weight indicates strength
        if edge.weight > 0.8:
            factors.append("strong_relationship")

        return factors

    def _calculate_trend(
        self,
        propagations: List[RiskPropagation],
    ) -> str:
        """Calculate risk trend from propagations."""
        if not propagations:
            return "stable"

        # Group by hop count
        by_hop: Dict[int, List[float]] = defaultdict(list)
        for p in propagations:
            by_hop[p.hop_count].append(p.risk_score)

        if len(by_hop) < 2:
            return "stable"

        # Compare early vs late hops
        first_hops = [s for scores in list(by_hop.values())[:2] for s in scores]
        last_hops = [s for scores in list(by_hop.values())[-2:] for s in scores]

        if not first_hops or not last_hops:
            return "stable"

        avg_early = sum(first_hops) / len(first_hops)
        avg_late = sum(last_hops) / len(last_hops)

        if avg_late > avg_early * 1.2:
            return "increasing"
        elif avg_late < avg_early * 0.8:
            return "decreasing"
        else:
            return "stable"

    def _generate_risk_recommendations(
        self,
        entity: FederatedEntity,
        propagations: List[RiskPropagation],
    ) -> List[str]:
        """Generate risk mitigation recommendations."""
        recommendations = []

        if entity.risk_score >= self._config.high_risk_threshold:
            recommendations.append("Consider immediate investigation")
            recommendations.append("Enable enhanced monitoring")

        if len(propagations) > 10:
            recommendations.append("High propagation - review network connections")
            recommendations.append("Consider isolating high-risk entities")

        # Check for rapid spread
        high_hop_propagations = [p for p in propagations if p.hop_count > 3]
        if len(high_hop_propagations) > 5:
            recommendations.append("Rapid risk spread detected - escalate")

        if not recommendations:
            recommendations.append("Continue monitoring")

        return recommendations


# Global engine instance
_engine: Optional[RiskPropagationEngine] = None


def get_risk_propagation_engine() -> RiskPropagationEngine:
    """Get the global risk propagation engine instance."""
    global _engine
    if _engine is None:
        _engine = RiskPropagationEngine()
    return _engine