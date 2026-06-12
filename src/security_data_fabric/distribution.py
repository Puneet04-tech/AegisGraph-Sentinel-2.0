"""
Intelligence Distribution Engine.

Distributes data across the AegisGraph ecosystem.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .store import SecurityDataFabricStore, get_fabric_store


class DistributionEngine:
    """Engine for distributing intelligence data."""

    def __init__(self, store: Optional[SecurityDataFabricStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_fabric_store()
        self._distribution_targets: Dict[str, Dict[str, Any]] = {}

    def register_target(
        self,
        target_id: str,
        target_type: str,
        endpoint: str,
        capabilities: List[str],
    ) -> Dict[str, Any]:
        """Register a distribution target."""
        self._distribution_targets[target_id] = {
            "target_id": target_id,
            "target_type": target_type,
            "endpoint": endpoint,
            "capabilities": capabilities,
            "status": "active",
            "registered_at": datetime.now(timezone.utc),
        }
        
        return self._distribution_targets[target_id]

    def distribute(
        self,
        source_asset_id: str,
        target_ids: List[str],
        distribution_type: str = "push",
    ) -> Dict[str, Any]:
        """Distribute data to targets."""
        source = self.store.get_asset(source_asset_id)
        if not source:
            return {"success": False, "error": "Source asset not found"}
        
        results = []
        for target_id in target_ids:
            if target_id not in self._distribution_targets:
                results.append({"target_id": target_id, "status": "not_found"})
                continue
            
            results.append({
                "target_id": target_id,
                "status": "distributed",
                "asset_id": source_asset_id,
                "distribution_type": distribution_type,
                "distributed_at": datetime.now(timezone.utc).isoformat(),
            })
        
        return {
            "success": True,
            "distribution_id": f"dist-{uuid.uuid4().hex[:12]}",
            "source_asset_id": source_asset_id,
            "results": results,
        }

    def get_target(self, target_id: str) -> Optional[Dict[str, Any]]:
        """Get a distribution target."""
        return self._distribution_targets.get(target_id)

    def get_all_targets(self) -> List[Dict[str, Any]]:
        """Get all distribution targets."""
        return list(self._distribution_targets.values())

    def get_distribution_history(self, source_asset_id: str) -> List[Dict[str, Any]]:
        """Get distribution history for an asset."""
        return [
            {"target_id": tid, "status": "distributed"}
            for tid in self._distribution_targets
        ]


# Singleton instance
_engine: Optional[DistributionEngine] = None


def get_distribution_engine() -> DistributionEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = DistributionEngine()
    return _engine


def reset_distribution_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None