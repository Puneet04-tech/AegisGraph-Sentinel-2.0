"""
Intelligence Router.

Routes intelligence across the mesh.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    Intelligence,
    IntelligenceType,
    ShareLevel,
)
from .store import SecurityMeshStore, get_mesh_store


class IntelligenceRouter:
    """Router for intelligence sharing."""

    def __init__(self, store: Optional[SecurityMeshStore] = None) -> None:
        """Initialize the router."""
        self.store = store or get_mesh_store()

    def share_intelligence(
        self,
        source_node: str,
        intelligence_type: str,
        title: str,
        description: str,
        indicators: Optional[List[Dict[str, Any]]] = None,
        confidence: float = 0.8,
        share_level: str = "partial",
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Intelligence:
        """Share intelligence across the mesh."""
        intel_id = f"intel-{uuid.uuid4().hex[:12]}"
        
        intel = Intelligence(
            intel_id=intel_id,
            source_node=source_node,
            intelligence_type=IntelligenceType(intelligence_type),
            title=title,
            description=description,
            indicators=indicators or [],
            confidence=confidence,
            share_level=ShareLevel(share_level),
            tags=tags or [],
            metadata=metadata or {},
        )
        
        self.store.store_intelligence(intel)
        
        self.store.log_audit(
            user_id=source_node,
            action="intelligence_shared",
            node_id=source_node,
            details={
                "intel_id": intel_id,
                "type": intelligence_type,
                "title": title,
            },
        )
        
        return intel

    def get_intelligence(
        self,
        intel_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Get intelligence by ID."""
        intel = self.store.get_intelligence(intel_id)
        if not intel:
            return None
        
        return self._intel_to_dict(intel)

    def _intel_to_dict(self, intel: Intelligence) -> Dict[str, Any]:
        """Convert intelligence to dictionary."""
        return {
            "intel_id": intel.intel_id,
            "source_node": intel.source_node,
            "type": intel.intelligence_type.value,
            "title": intel.title,
            "description": intel.description,
            "indicators": intel.indicators,
            "confidence": intel.confidence,
            "share_level": intel.share_level.value,
            "tags": intel.tags,
            "created_at": intel.created_at.isoformat(),
        }

    def search_intelligence(
        self,
        query: str,
        intelligence_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search intelligence."""
        type_enum = IntelligenceType(intelligence_type) if intelligence_type else None
        results = self.store.search_intelligence(query, type_enum)
        
        return [self._intel_to_dict(i) for i in results]

    def get_intelligence_for_node(
        self,
        node_type: str,
    ) -> List[Dict[str, Any]]:
        """Get intelligence relevant for a node type."""
        from .models import NodeType
        type_enum = NodeType(node_type)
        results = self.store.get_intelligence_for_node(type_enum)
        
        return [self._intel_to_dict(i) for i in results]

    def get_cross_domain_intelligence(
        self,
    ) -> List[Dict[str, Any]]:
        """Get intelligence from different domains."""
        results = []
        seen_types = set()
        
        for intel in self.store._intelligence.values():
            if intel.intelligence_type not in seen_types:
                results.append(self._intel_to_dict(intel))
                seen_types.add(intel.intelligence_type)
        
        return results


# Singleton instance
_router: Optional[IntelligenceRouter] = None


def get_intelligence_router() -> IntelligenceRouter:
    """Get the global router instance."""
    global _router
    if _router is None:
        _router = IntelligenceRouter()
    return _router


def reset_intelligence_router() -> None:
    """Reset the global router."""
    global _router
    _router = None