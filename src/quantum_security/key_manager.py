"""
Key Lifecycle Manager.

Manages cryptographic key lifecycle operations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import KeyLifecycleRecord
from .store import QuantumSecurityStore, get_quantum_store


class KeyLifecycleManager:
    """Engine for key lifecycle management."""

    def __init__(self, store: Optional[QuantumSecurityStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_quantum_store()

    def create_key(
        self,
        key_id: str,
        algorithm: str,
        created_by: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record key creation."""
        record = KeyLifecycleRecord(
            record_id=str(uuid.uuid4()),
            key_id=key_id,
            event="created",
            performed_by=created_by,
            timestamp=datetime.now(timezone.utc),
            details=metadata or {},
        )
        
        self.store.add_lifecycle_record(record)
        
        self.store.log_audit(
            user_id=created_by,
            action="key_created",
            resource_type="crypto_key",
            resource_id=key_id,
            details=metadata or {},
        )
        
        return {
            "record_id": record.record_id,
            "key_id": key_id,
            "event": "created",
            "timestamp": record.timestamp.isoformat(),
        }

    def rotate_key(
        self,
        key_id: str,
        rotated_by: str,
        reason: str = "scheduled",
    ) -> Dict[str, Any]:
        """Record key rotation."""
        record = KeyLifecycleRecord(
            record_id=str(uuid.uuid4()),
            key_id=key_id,
            event="rotated",
            performed_by=rotated_by,
            timestamp=datetime.now(timezone.utc),
            details={"reason": reason},
        )
        
        self.store.add_lifecycle_record(record)
        
        asset = self.store.get_asset(key_id)
        if asset:
            asset.last_rotated = datetime.now(timezone.utc)
        
        self.store.log_audit(
            user_id=rotated_by,
            action="key_rotated",
            resource_type="crypto_key",
            resource_id=key_id,
            details={"reason": reason},
        )
        
        return {
            "record_id": record.record_id,
            "key_id": key_id,
            "event": "rotated",
            "timestamp": record.timestamp.isoformat(),
        }

    def destroy_key(
        self,
        key_id: str,
        destroyed_by: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Record key destruction."""
        record = KeyLifecycleRecord(
            record_id=str(uuid.uuid4()),
            key_id=key_id,
            event="destroyed",
            performed_by=destroyed_by,
            timestamp=datetime.now(timezone.utc),
            details={"reason": reason},
        )
        
        self.store.add_lifecycle_record(record)
        
        self.store.log_audit(
            user_id=destroyed_by,
            action="key_destroyed",
            resource_type="crypto_key",
            resource_id=key_id,
            details={"reason": reason},
        )
        
        return {
            "record_id": record.record_id,
            "key_id": key_id,
            "event": "destroyed",
            "timestamp": record.timestamp.isoformat(),
        }

    def get_key_history(self, key_id: str) -> List[Dict[str, Any]]:
        """Get lifecycle history for a key."""
        records = self.store.get_lifecycle_records(key_id)
        
        return [
            {
                "record_id": r.record_id,
                "event": r.event,
                "performed_by": r.performed_by,
                "timestamp": r.timestamp.isoformat(),
                "details": r.details,
            }
            for r in records
        ]

    def get_rotation_due_keys(self, days_threshold: int = 30) -> List[str]:
        """Get keys due for rotation."""
        now = datetime.now(timezone.utc)
        threshold = datetime.fromtimestamp(
            now.timestamp() - days_threshold * 86400,
            tz=timezone.utc,
        )
        
        due_keys = []
        for asset in self.store._assets.values():
            if asset.last_rotated and asset.last_rotated <= threshold:
                due_keys.append(asset.asset_id)
        
        return due_keys


# Singleton instance
_manager: Optional[KeyLifecycleManager] = None


def get_key_manager() -> KeyLifecycleManager:
    """Get the global manager instance."""
    global _manager
    if _manager is None:
        _manager = KeyLifecycleManager()
    return _manager


def reset_key_manager() -> None:
    """Reset the global manager."""
    global _manager
    _manager = None