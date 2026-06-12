"""
Federated Search Engine for cross-organization intelligence search.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import uuid

from .models import (
    EntityType,
    FederatedEntity,
    ThreatLevel,
    IntelligenceSource,
)
from .store import GlobalIntelligenceStore, get_global_intelligence_store
from .federation_engine import FederationEngine, get_federation_engine


@dataclass
class SearchResult:
    """Result of a federated search."""
    result_id: str
    query_id: str
    entity: FederatedEntity
    source: IntelligenceSource
    partner_id: Optional[str]
    relevance_score: float
    matched_fields: List[str]
    highlighted_content: Optional[str]
    returned_at: datetime


@dataclass
class SearchQuery:
    """Query for federated search."""
    query_id: str
    query_text: str
    entity_types: List[EntityType]
    threat_levels: List[ThreatLevel]
    date_range_start: Optional[datetime]
    date_range_end: Optional[datetime]
    include_internal: bool = True
    include_federation: bool = True
    max_results_per_source: int = 20
    fuzzy_match: bool = True


class FederatedSearchEngine:
    """
    Performs federated search across multiple intelligence sources.

    Handles:
    - Cross-organization search
    - Query routing and optimization
    - Result aggregation and ranking
    - Search caching
    """

    def __init__(
        self,
        store: Optional[GlobalIntelligenceStore] = None,
        federation_engine: Optional[FederationEngine] = None,
    ):
        self._store = store or get_global_intelligence_store()
        self._federation = federation_engine or get_federation_engine()
        self._search_cache: Dict[str, Tuple[List[SearchResult], datetime]] = {}

    def search(
        self,
        query: SearchQuery,
    ) -> List[SearchResult]:
        """Execute a federated search across all sources."""
        results: List[SearchResult] = []

        # Search internal sources
        if query.include_internal:
            internal_results = self._search_internal(query)
            results.extend(internal_results)

        # Search federation partners
        if query.include_federation:
            federation_results = self._search_federation(query)
            results.extend(federation_results)

        # Rank and deduplicate results
        results = self._rank_and_deduplicate(results)

        return results[: query.max_results_per_source * 3]

    def search_by_example(
        self,
        example_entity: FederatedEntity,
        limit: int = 20,
    ) -> List[SearchResult]:
        """Search for entities similar to an example."""
        results = []

        # Search internal sources
        all_entities = list(self._store._entities.values())
        for entity in all_entities:
            if entity.entity_id == example_entity.entity_id:
                continue

            score = self._calculate_similarity(example_entity, entity)
            if score > 0.3:
                result = SearchResult(
                    result_id=str(uuid.uuid4()),
                    query_id="",
                    entity=entity,
                    source=IntelligenceSource.INTERNAL,
                    partner_id="self",
                    relevance_score=score,
                    matched_fields=self._get_matched_fields(example_entity, entity),
                    highlighted_content=None,
                    returned_at=datetime.now(timezone.utc),
                )
                results.append(result)

        # Sort by score
        results.sort(key=lambda r: r.relevance_score, reverse=True)

        return results[:limit]

    def aggregate_metrics(
        self,
        entity_ids: List[str],
    ) -> Dict[str, Any]:
        """Aggregate metrics across multiple entities."""
        entities = []
        for eid in entity_ids:
            entity = self._store.get_entity(eid)
            if entity:
                entities.append(entity)

        if not entities:
            return {"error": "No entities found"}

        threat_dist = {}
        type_dist = {}
        total_risk = 0.0

        for entity in entities:
            # Threat level distribution
            level = entity.threat_level.value
            threat_dist[level] = threat_dist.get(level, 0) + 1

            # Entity type distribution
            etype = entity.entity_type.value
            type_dist[etype] = type_dist.get(etype, 0) + 1

            total_risk += entity.risk_score

        return {
            "entity_count": len(entities),
            "avg_risk_score": total_risk / len(entities),
            "max_risk_score": max(e.risk_score for e in entities),
            "threat_level_distribution": threat_dist,
            "entity_type_distribution": type_dist,
            "unique_partners": len(set(e.partner_id for e in entities)),
        }

    def _search_internal(
        self,
        query: SearchQuery,
    ) -> List[SearchResult]:
        """Search internal intelligence sources."""
        results = []

        for entity in self._store._entities.values():
            score = self._match_query(entity, query)
            if score > 0:
                result = SearchResult(
                    result_id=str(uuid.uuid4()),
                    query_id=query.query_id,
                    entity=entity,
                    source=IntelligenceSource.INTERNAL,
                    partner_id="self",
                    relevance_score=score,
                    matched_fields=self._get_query_matched_fields(entity, query),
                    highlighted_content=None,
                    returned_at=datetime.now(timezone.utc),
                )
                results.append(result)

        return results

    def _search_federation(
        self,
        query: SearchQuery,
    ) -> List[SearchResult]:
        """Search federation partner sources."""
        results = []

        # Get active partners
        partners = self._store.get_active_partners()

        for partner in partners:
            if partner.partner_id == "self":
                continue

            # Request intelligence from partner (simulated)
            partner_query = {
                "query": query.query_text,
                "entity_type": [e.value for e in query.entity_types] if query.entity_types else None,
                "threat_levels": [t.value for t in query.threat_levels] if query.threat_levels else None,
                "max_results": query.max_results_per_source,
            }

            # Get matching entities from partner's shared data
            partner_entities = self._federation.request_intelligence(
                "self",
                partner_query,
            )

            for entity in partner_entities:
                result = SearchResult(
                    result_id=str(uuid.uuid4()),
                    query_id=query.query_id,
                    entity=entity,
                    source=IntelligenceSource.FEDERATION,
                    partner_id=partner.partner_id,
                    relevance_score=0.7,  # Default score for federation results
                    matched_fields=["federation_match"],
                    highlighted_content=None,
                    returned_at=datetime.now(timezone.utc),
                )
                results.append(result)

        return results

    def _match_query(
        self,
        entity: FederatedEntity,
        query: SearchQuery,
    ) -> float:
        """Calculate how well an entity matches a query."""
        score = 0.0

        # Check entity type filter
        if query.entity_types and entity.entity_type not in query.entity_types:
            return 0.0

        # Check threat level filter
        if query.threat_levels and entity.threat_level not in query.threat_levels:
            return 0.0

        # Check date range
        if query.date_range_start and entity.first_seen < query.date_range_start:
            return 0.0
        if query.date_range_end and entity.first_seen > query.date_range_end:
            return 0.0

        # Text matching
        if query.query_text:
            query_lower = query.query_text.lower()
            score += 0.3

            # Check attributes
            for key, value in entity.attributes.items():
                if query_lower in str(value).lower():
                    score += 0.2

            # Check threat indicators
            for indicator in entity.threat_indicators:
                if query_lower in indicator.lower():
                    score += 0.2

        # Base score for matching filters
        score += 0.2

        return min(1.0, score)

    def _calculate_similarity(
        self,
        entity1: FederatedEntity,
        entity2: FederatedEntity,
    ) -> float:
        """Calculate similarity between two entities."""
        score = 0.0

        # Same type
        if entity1.entity_type == entity2.entity_type:
            score += 0.3

        # Shared attributes
        shared = set(entity1.attributes.keys()) & set(entity2.attributes.keys())
        if shared:
            matches = 0
            for key in shared:
                if entity1.attributes[key] == entity2.attributes[key]:
                    matches += 1
            score += (matches / len(shared)) * 0.4 if shared else 0

        # Threat level similarity
        level_map = {
            ThreatLevel.UNKNOWN: 0,
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4,
        }
        level_diff = abs(level_map.get(entity1.threat_level, 0) - level_map.get(entity2.threat_level, 0))
        score += max(0, 1 - level_diff / 4) * 0.3

        return score

    def _get_matched_fields(
        self,
        example: FederatedEntity,
        candidate: FederatedEntity,
    ) -> List[str]:
        """Get list of fields that matched."""
        matched = []

        if example.entity_type == candidate.entity_type:
            matched.append("entity_type")

        for key in example.attributes:
            if key in candidate.attributes:
                if example.attributes[key] == candidate.attributes[key]:
                    matched.append(f"attribute:{key}")

        return matched

    def _get_query_matched_fields(
        self,
        entity: FederatedEntity,
        query: SearchQuery,
    ) -> List[str]:
        """Get fields that matched the query."""
        matched = []

        if entity.entity_type in query.entity_types:
            matched.append("entity_type")

        if entity.threat_level in query.threat_levels:
            matched.append("threat_level")

        return matched

    def _rank_and_deduplicate(
        self,
        results: List[SearchResult],
    ) -> List[SearchResult]:
        """Rank results and remove duplicates."""
        # Remove duplicates based on entity_id
        seen: Dict[str, SearchResult] = {}
        for result in results:
            if result.entity.entity_id not in seen:
                seen[result.entity.entity_id] = result
            else:
                # Keep the one with higher score
                if result.relevance_score > seen[result.entity.entity_id].relevance_score:
                    seen[result.entity.entity_id] = result

        # Sort by relevance score
        ranked = list(seen.values())
        ranked.sort(key=lambda r: r.relevance_score, reverse=True)

        return ranked


# Global engine instance
_engine: Optional[FederatedSearchEngine] = None


def get_federated_search_engine() -> FederatedSearchEngine:
    """Get the global federated search engine instance."""
    global _engine
    if _engine is None:
        _engine = FederatedSearchEngine()
    return _engine