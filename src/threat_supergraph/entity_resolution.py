"""
Global Entity Resolution Engine
Resolves and correlates entities across different data sources.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from .models import EntityType, SupergraphNode


class EntityResolutionEngine:
    """Engine for resolving and correlating entities."""
    
    def __init__(self):
        self._canonical_ids: Dict[str, str] = {}
        self._aliases: Dict[str, Set[str]] = {}
        self._resolution_cache: Dict[str, str] = {}
    
    def resolve(
        self,
        entity_type: EntityType,
        identifier: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Resolve an entity to its canonical ID."""
        cache_key = f"{entity_type.value}:{identifier}"
        
        if cache_key in self._resolution_cache:
            return self._resolution_cache[cache_key]
        
        canonical_id = self._find_canonical(entity_type, identifier, attributes)
        
        if canonical_id:
            self._resolution_cache[cache_key] = canonical_id
            return canonical_id
        
        return str(uuid4())
    
    def _find_canonical(
        self,
        entity_type: EntityType,
        identifier: str,
        attributes: Optional[Dict[str, Any]],
    ) -> Optional[str]:
        """Find canonical ID for an entity."""
        if identifier in self._canonical_ids:
            return self._canonical_ids[identifier]
        
        return None
    
    def merge_entities(
        self,
        source_id: str,
        target_id: str,
    ) -> str:
        """Merge two entities."""
        canonical_id = str(uuid4())
        
        if source_id in self._canonical_ids:
            self._canonical_ids[source_id] = canonical_id
        if target_id in self._canonical_ids:
            self._canonical_ids[target_id] = canonical_id
        
        self._canonical_ids[source_id] = canonical_id
        self._canonical_ids[target_id] = canonical_id
        
        return canonical_id
    
    def link_alias(
        self,
        canonical_id: str,
        alias: str,
    ) -> None:
        """Link an alias to a canonical ID."""
        if canonical_id not in self._aliases:
            self._aliases[canonical_id] = set()
        self._aliases[canonical_id].add(alias)
        self._resolution_cache[alias] = canonical_id
    
    def get_resolved_entities(
        self,
        entity_type: EntityType,
    ) -> List[str]:
        """Get all resolved entities of a type."""
        resolved = []
        for canonical_id, aliases in self._aliases.items():
            resolved.append(canonical_id)
        return resolved
    
    def get_resolution_stats(self) -> Dict[str, Any]:
        """Get resolution statistics."""
        return {
            "total_resolved": len(self._canonical_ids),
            "total_aliases": sum(len(a) for a in self._aliases.values()),
            "cache_size": len(self._resolution_cache),
        }


def get_entity_resolution_engine() -> EntityResolutionEngine:
    """Get the global entity resolution engine instance."""
    global _entity_resolution_engine
    if _entity_resolution_engine is None:
        _entity_resolution_engine = EntityResolutionEngine()
    return _entity_resolution_engine


_entity_resolution_engine: Optional[EntityResolutionEngine] = None