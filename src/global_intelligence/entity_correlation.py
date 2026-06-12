"""
Entity Correlation Engine for cross-institution entity matching.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple
import uuid

from .models import (
    CorrelationStrength,
    CorrelationResult,
    EntityMatch,
    EntityType,
    FederatedEntity,
    ThreatLevel,
)
from .store import GlobalIntelligenceStore, get_global_intelligence_store


@dataclass
class CorrelationConfig:
    """Configuration for entity correlation."""
    exact_match_threshold: float = 1.0
    strong_match_threshold: float = 0.9
    moderate_match_threshold: float = 0.7
    weak_match_threshold: float = 0.5
    fuzzy_match_enabled: bool = True
    phonetic_match_enabled: bool = True


@dataclass
class EntityFingerprint:
    """Fingerprint for entity matching."""
    entity_id: str
    fingerprint_type: str
    hash_value: str
    attributes: Dict[str, Any]
    created_at: datetime


class EntityCorrelationEngine:
    """
    Correlates entities across institutions and fraud intelligence sources.

    Handles:
    - Exact and fuzzy entity matching
    - Cross-institution entity correlation
    - Identity resolution
    - Entity deduplication
    """

    def __init__(
        self,
        store: Optional[GlobalIntelligenceStore] = None,
        config: Optional[CorrelationConfig] = None,
    ):
        self._store = store or get_global_intelligence_store()
        self._config = config or CorrelationConfig()
        self._fingerprints: Dict[str, EntityFingerprint] = {}

    def correlate_entities(
        self,
        entity: FederatedEntity,
        candidates: Optional[List[FederatedEntity]] = None,
    ) -> CorrelationResult:
        """Correlate an entity with potential matches."""
        if candidates is None:
            candidates = list(self._store._entities.values())

        matches: List[EntityMatch] = []

        for candidate in candidates:
            if candidate.entity_id == entity.entity_id:
                continue

            score, strength, reasons = self._calculate_correlation(entity, candidate)

            if score >= self._config.weak_match_threshold:
                match = EntityMatch(
                    match_id=str(uuid.uuid4()),
                    entity_1_id=entity.entity_id,
                    entity_2_id=candidate.entity_id,
                    correlation_score=score,
                    strength=strength,
                    match_type=self._determine_match_type(entity, candidate),
                    shared_attributes=reasons,
                    confidence=score,
                    discovered_at=datetime.now(timezone.utc),
                    verified=False,
                )
                matches.append(match)

        # Sort by score
        matches.sort(key=lambda m: m.correlation_score, reverse=True)

        return CorrelationResult(
            result_id=str(uuid.uuid4()),
            primary_entity_id=entity.entity_id,
            total_candidates=len(candidates),
            matches_found=len(matches),
            matches=matches[:10],
            avg_score=sum(m.correlation_score for m in matches) / len(matches) if matches else 0,
            analyzed_at=datetime.now(timezone.utc),
        )

    def correlate_batch(
        self,
        entities: List[FederatedEntity],
    ) -> List[CorrelationResult]:
        """Correlate multiple entities."""
        results = []
        for entity in entities:
            result = self.correlate_entities(entity)
            results.append(result)
        return results

    def resolve_identity(
        self,
        entity_ids: List[str],
    ) -> Dict[str, Any]:
        """Resolve multiple entity IDs to a single identity."""
        entities = []
        for eid in entity_ids:
            entity = self._store.get_entity(eid)
            if entity:
                entities.append(entity)

        if len(entities) < 2:
            return {"resolved": len(entities) == 1, "entities": entity_ids}

        # Calculate correlation matrix
        correlation_scores = {}
        for i, e1 in enumerate(entities):
            for e2 in entities[i + 1 :]:
                score, _, _ = self._calculate_correlation(e1, e2)
                correlation_scores[(e1.entity_id, e2.entity_id)] = score

        # Check if all entities are strongly correlated
        avg_score = (
            sum(correlation_scores.values()) / len(correlation_scores)
            if correlation_scores
            else 0
        )

        return {
            "resolved": avg_score >= self._config.strong_match_threshold,
            "entities": entity_ids,
            "correlation_matrix": correlation_scores,
            "average_score": avg_score,
            "representative_id": entities[0].entity_id,
        }

    def find_similar_entities(
        self,
        entity: FederatedEntity,
        limit: int = 10,
    ) -> List[Tuple[FederatedEntity, float]]:
        """Find entities similar to the given entity."""
        all_entities = list(self._store._entities.values())
        similarities = []

        for candidate in all_entities:
            if candidate.entity_id == entity.entity_id:
                continue

            score, _, _ = self._calculate_correlation(entity, candidate)
            if score >= self._config.weak_match_threshold:
                similarities.append((candidate, score))

        similarities.sort(key=lambda x: x[1], reverse=True)
        return similarities[:limit]

    def _calculate_correlation(
        self,
        entity1: FederatedEntity,
        entity2: FederatedEntity,
    ) -> Tuple[float, CorrelationStrength, List[str]]:
        """Calculate correlation between two entities."""
        scores: List[float] = []
        reasons: List[str] = []

        # Type match
        if entity1.entity_type == entity2.entity_type:
            scores.append(0.2)
            reasons.append("Same entity type")

        # Attribute matching
        shared_keys = set(entity1.attributes.keys()) & set(entity2.attributes.keys())
        if shared_keys:
            matches = 0
            for key in shared_keys:
                if self._values_match(
                    entity1.attributes[key], entity2.attributes[key]
                ):
                    matches += 1
            attr_score = matches / len(shared_keys) if shared_keys else 0
            scores.append(attr_score * 0.4)
            if matches > 0:
                reasons.append(f"{matches} shared attributes")

        # Fuzzy matching for strings
        if self._config.fuzzy_match_enabled:
            fuzzy_score = self._fuzzy_match(entity1, entity2)
            if fuzzy_score > 0:
                scores.append(fuzzy_score * 0.3)

        # Threat level correlation
        threat_score = self._threat_level_score(entity1.threat_level, entity2.threat_level)
        scores.append(threat_score * 0.1)
        if threat_score > 0.5:
            reasons.append("Similar threat levels")

        # Total score
        total_score = sum(scores) if scores else 0

        # Determine strength
        if total_score >= self._config.exact_match_threshold:
            strength = CorrelationStrength.DEFINITIVE
        elif total_score >= self._config.strong_match_threshold:
            strength = CorrelationStrength.STRONG
        elif total_score >= self._config.moderate_match_threshold:
            strength = CorrelationStrength.MODERATE
        else:
            strength = CorrelationStrength.WEAK

        return total_score, strength, reasons

    def _values_match(self, val1: Any, val2: Any) -> bool:
        """Check if two values match."""
        if val1 == val2:
            return True

        if isinstance(val1, str) and isinstance(val2, str):
            return self._fuzzy_compare(val1, val2) > 0.9

        if isinstance(val1, (int, float)) and isinstance(val2, (int, float)):
            return abs(val1 - val2) < 0.01

        return False

    def _fuzzy_match(self, entity1: FederatedEntity, entity2: FederatedEntity) -> float:
        """Perform fuzzy matching on entity attributes."""
        max_score = 0.0

        # Compare all string attributes
        for key in entity1.attributes:
            if key in entity2.attributes:
                val1 = str(entity1.attributes[key])
                val2 = str(entity2.attributes[key])
                score = self._fuzzy_compare(val1, val2)
                max_score = max(max_score, score)

        return max_score

    def _fuzzy_compare(self, str1: str, str2: str) -> float:
        """Compare two strings using sequence matching."""
        return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()

    def _threat_level_score(self, level1: ThreatLevel, level2: ThreatLevel) -> float:
        """Calculate score based on threat level similarity."""
        level_order = {
            ThreatLevel.UNKNOWN: 0,
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4,
        }

        diff = abs(level_order.get(level1, 0) - level_order.get(level2, 0))
        return max(0, 1 - (diff / 4))

    def _determine_match_type(
        self, entity1: FederatedEntity, entity2: FederatedEntity
    ) -> str:
        """Determine the type of match."""
        if entity1.entity_type == entity2.entity_type:
            return "same_type"

        if entity1.entity_type in (EntityType.PERSON, EntityType.ACCOUNT):
            return "account_person"

        if entity1.entity_type == EntityType.DEVICE and entity2.entity_type == EntityType.IP_ADDRESS:
            return "device_ip"

        return "cross_type"


# Global engine instance
_engine: Optional[EntityCorrelationEngine] = None


def get_entity_correlation_engine() -> EntityCorrelationEngine:
    """Get the global entity correlation engine instance."""
    global _engine
    if _engine is None:
        _engine = EntityCorrelationEngine()
    return _engine