"""
Crypto Inventory Engine.

Manages cryptographic asset inventory.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import CryptoAlgorithm, CryptoAsset, CryptoType
from .store import QuantumSecurityStore, get_quantum_store


class CryptoInventoryEngine:
    """Engine for crypto asset inventory."""

    def __init__(self, store: Optional[QuantumSecurityStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_quantum_store()

    def register_asset(
        self,
        name: str,
        algorithm: str,
        crypto_type: str,
        key_size: int,
        usage: str,
        system: str,
        location: str,
        owner: Optional[str] = None,
        quantum_resistant: bool = False,
    ) -> CryptoAsset:
        """Register a crypto asset."""
        asset_id = f"crypto-{uuid.uuid4().hex[:12]}"
        
        asset = CryptoAsset(
            asset_id=asset_id,
            name=name,
            algorithm=CryptoAlgorithm(algorithm),
            crypto_type=CryptoType(crypto_type),
            key_size=key_size,
            usage=usage,
            system=system,
            location=location,
            owner=owner,
            quantum_resistant=quantum_resistant,
        )
        
        self.store.register_asset(asset)
        
        self.store.log_audit(
            user_id="system",
            action="asset_registered",
            resource_type="crypto_asset",
            resource_id=asset_id,
            details={"algorithm": algorithm, "system": system},
        )
        
        return asset

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Get asset details."""
        asset = self.store.get_asset(asset_id)
        if not asset:
            return None
        
        return self._asset_to_dict(asset)

    def _asset_to_dict(self, asset: CryptoAsset) -> Dict[str, Any]:
        """Convert asset to dictionary."""
        return {
            "asset_id": asset.asset_id,
            "name": asset.name,
            "algorithm": asset.algorithm.value,
            "crypto_type": asset.crypto_type.value,
            "key_size": asset.key_size,
            "usage": asset.usage,
            "system": asset.system,
            "location": asset.location,
            "owner": asset.owner,
            "quantum_resistant": asset.quantum_resistant,
            "rotation_period_days": asset.rotation_period_days,
            "last_rotated": asset.last_rotated.isoformat() if asset.last_rotated else None,
            "created_at": asset.created_at.isoformat(),
        }

    def get_all_assets(
        self,
        algorithm: Optional[str] = None,
        system: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get all assets with optional filtering."""
        assets = list(self.store._assets.values())
        
        if algorithm:
            algo_enum = CryptoAlgorithm(algorithm)
            assets = [a for a in assets if a.algorithm == algo_enum]
        
        if system:
            assets = [a for a in assets if a.system == system]
        
        return [self._asset_to_dict(a) for a in assets]

    def get_vulnerable_assets(self) -> List[Dict[str, Any]]:
        """Get quantum-vulnerable assets."""
        assets = self.store.get_vulnerable_assets()
        return [self._asset_to_dict(a) for a in assets]

    def update_rotation_info(
        self,
        asset_id: str,
        rotation_period_days: int,
    ) -> bool:
        """Update rotation information."""
        asset = self.store.get_asset(asset_id)
        if not asset:
            return False
        
        asset.rotation_period_days = rotation_period_days
        asset.last_rotated = datetime.now(timezone.utc)
        return True

    def get_inventory_summary(self) -> Dict[str, Any]:
        """Get inventory summary."""
        assets = list(self.store._assets.values())
        
        by_algorithm: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        by_system: Dict[str, int] = {}
        
        for asset in assets:
            algo = asset.algorithm.value
            by_algorithm[algo] = by_algorithm.get(algo, 0) + 1
            
            crypto_type = asset.crypto_type.value
            by_type[crypto_type] = by_type.get(crypto_type, 0) + 1
            
            by_system[asset.system] = by_system.get(asset.system, 0) + 1
        
        return {
            "total_assets": len(assets),
            "vulnerable_assets": len(self.store.get_vulnerable_assets()),
            "by_algorithm": by_algorithm,
            "by_type": by_type,
            "by_system": by_system,
        }


# Singleton instance
_engine: Optional[CryptoInventoryEngine] = None


def get_crypto_inventory_engine() -> CryptoInventoryEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = CryptoInventoryEngine()
    return _engine


def reset_crypto_inventory_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None