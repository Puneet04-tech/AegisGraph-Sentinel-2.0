"""
Federation Engine.

Manages federated knowledge graph and cross-domain correlation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    Intelligence,
    IntelligenceType,
    KnowledgeGraphEntry,
)
from .store import SecurityMeshStore, get_mesh_store


class FederationEngine:
    """Engine for federation and correlation."""

    def __init__(self, store: Optional[SecurityMeshStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_mesh_store()

    def add_knowledge_entry(
        self,
        entity_type: str,
        entity_id: str,
        attributes: Dict[str, Any],
        relationships: Optional[List[Dict[str, Any]]] = None,
        source_node: str = "system",
    ) -> KnowledgeGraphEntry:
        """Add an entry to the knowledge graph."""
        entry_id = f"kg-{uuid.uuid4().hex[:12]}"
        
        entry = KnowledgeGraphEntry(
            entry_id=entry_id,
            entity_type=entity_type,
            entity_id=entity_id,
            attributes=attributes,
            relationships=relationships or [],
            source_node=source_node,
        )
        
        self.store.add_knowledge_entry(entry)
        
        self.store.log_audit(
            user_id=source_node,
            action="knowledge_entry_added",
            details={"entry_id": entry_id, "entity_type": entity_type},
        )
        
        return entry

    def get_knowledge_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        """Get a knowledge entry."""
        entry = self.store.get_knowledge_entry(entry_id)
        if not entry:
            return None
        
        return self._entry_to_dict(entry)

    def _entry_to_dict(self, entry: KnowledgeGraphEntry) -> Dict[str, Any]:
        """Convert entry to dictionary."""
        return {
            "entry_id": entry.entry_id,
            "entity_type": entry.entity_type,
            "entity_id": entry.entity_id,
            "attributes": entry.attributes,
            "relationships": entry.relationships,
            "source_node": entry.source_node,
            "created_at": entry.created_at.isoformat(),
        }

    def find_correlations(
        self,
        entity_id: str,
    ) -> List[Dict[str, Any]]:
        """Find correlations for an entity."""
        entries = self.store.get_knowledge_by_entity(entity_id)
        correlations = []
        
        for entry in entries:
            relationships = entry.relationships
            for rel in relationships:
                if rel.get("target_entity_id"):
                    target_entries = self.store.get_knowledge_by_entity(
                        rel["target_entity_id"]
                    )
                    for target in target_entries:
                        if target.source_node != entry.source_node:
                            correlations.append({
                                "source_entry": self._entry_to_dict(entry),
                                "target_entry": self._entry_to_dict(target),
                                "relationship": rel.get("type"),
                            })
        
        return correlations

    def correlate_intelligence(
        self,
        intel_id: str,
    ) -> List[Dict[str, Any]]:
        """Correlate intelligence with knowledge graph."""
        intel = self.store.get_intelligence(intel_id)
        if not intel:
            return []
        
        correlations = []
        
        for indicator in intel.indicators:
            if "hash" in indicator:
                entries = self._find_by_attribute("hash", indicator["hash"])
                for entry in entries:
                    correlations.append({
                        "intel_id": intel_id,
                        "entry": self._entry_to_dict(entry),
                        "indicator": indicator,
                    })
            
            if "ip" in indicator:
                entries = self._find_by_attribute("ip", indicator["ip"])
                for entry in entries:
                    correlations.append({
                        "intel_id": intel_id,
                        "entry": self._entry_to_dict(entry),
                        "indicator": indicator,
                    })
        
        return correlations

    def _find_by_attribute(
        self,
        attr_name: str,
        attr_value: str,
    ) -> List[KnowledgeGraphEntry]:
        """Find entries by attribute."""
        results = []
        for entry in self.store._knowledge_graph.values():
            if entry.attributes.get(attr_name) == attr_value:
                results.append(entry)
        return results

    def get_cross_domain_insights(self) -> Dict[str, Any]:
        """Get cross-domain insights."""
        insights = {
            "domain_counts": {},
            "cross_domain_entities": [],
            "shared_indicators": [],
        }
        
        for entry in self.store._knowledge_graph.values():
            domain = entry.source_node
            insights["domain_counts"][domain] = insights["domain_counts"].get(domain, 0) + 1
        
        for intel in self.store._intelligence.values():
            if intel.intelligence_type == IntelligenceType.CAMPAIGN:
                insights["shared_indicators"].append({
                    "intel_id": intel.intel_id,
                    "title": intel.title,
                    "confidence": intel.confidence,
                })
        
        return insights


# Singleton instance
_engine: Optional[FederationEngine] = None


def get_federation_engine() -> FederationEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = FederationEngine()
    return _engine


def reset_federation_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None