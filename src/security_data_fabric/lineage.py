"""
Data Lineage Engine.

Tracks and manages data lineage across the fabric.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
import uuid

from .models import DataAsset, LineageRecord, LineageType
from .store import SecurityDataFabricStore, get_fabric_store


class LineageEngine:
    """Engine for tracking data lineage."""

    def __init__(self, store: Optional[SecurityDataFabricStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_fabric_store()

    def record_lineage(
        self,
        source_asset_id: str,
        target_asset_id: str,
        lineage_type: str,
        transformation_logic: Optional[str] = None,
        confidence: float = 1.0,
    ) -> LineageRecord:
        """Record a lineage relationship."""
        record_id = f"lin-{uuid.uuid4().hex[:12]}"
        
        record = LineageRecord(
            record_id=record_id,
            source_asset_id=source_asset_id,
            target_asset_id=target_asset_id,
            lineage_type=LineageType(lineage_type),
            transformation_logic=transformation_logic,
            confidence=confidence,
        )
        
        self.store.add_lineage(record)
        return record

    def get_upstream_lineage(self, asset_id: str, depth: int = 10) -> List[Dict[str, Any]]:
        """Get upstream lineage for an asset."""
        lineage = []
        visited: Set[str] = set()
        queue = [(asset_id, 0)]
        
        while queue:
            current_id, current_depth = queue.pop(0)
            if current_id in visited or current_depth >= depth:
                continue
            visited.add(current_id)
            
            records = self.store.get_lineage_for_asset(current_id)
            for record in records:
                if record.target_asset_id == current_id:
                    lineage.append({
                        "asset_id": record.source_asset_id,
                        "relationship": record.lineage_type.value,
                        "depth": current_depth + 1,
                        "confidence": record.confidence,
                        "transformation": record.transformation_logic,
                    })
                    queue.append((record.source_asset_id, current_depth + 1))
        
        return lineage

    def get_downstream_lineage(self, asset_id: str, depth: int = 10) -> List[Dict[str, Any]]:
        """Get downstream lineage for an asset."""
        lineage = []
        visited: Set[str] = set()
        queue = [(asset_id, 0)]
        
        while queue:
            current_id, current_depth = queue.pop(0)
            if current_id in visited or current_depth >= depth:
                continue
            visited.add(current_id)
            
            records = self.store.get_lineage_for_asset(current_id)
            for record in records:
                if record.source_asset_id == current_id:
                    lineage.append({
                        "asset_id": record.target_asset_id,
                        "relationship": record.lineage_type.value,
                        "depth": current_depth + 1,
                        "confidence": record.confidence,
                        "transformation": record.transformation_logic,
                    })
                    queue.append((record.target_asset_id, current_depth + 1))
        
        return lineage

    def get_full_lineage_graph(self, asset_id: str, max_depth: int = 5) -> Dict[str, Any]:
        """Get the full lineage graph for an asset."""
        upstream = self.get_upstream_lineage(asset_id, max_depth)
        downstream = self.get_downstream_lineage(asset_id, max_depth)
        
        return {
            "asset_id": asset_id,
            "upstream": upstream,
            "downstream": downstream,
            "upstream_count": len(upstream),
            "downstream_count": len(downstream),
        }

    def impact_analysis(self, asset_id: str) -> List[str]:
        """Perform impact analysis for an asset."""
        downstream = self.get_downstream_lineage(asset_id, 100)
        impacted = [d["asset_id"] for d in downstream]
        return impacted


# Singleton instance
_engine: Optional[LineageEngine] = None


def get_lineage_engine() -> LineageEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = LineageEngine()
    return _engine


def reset_lineage_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None