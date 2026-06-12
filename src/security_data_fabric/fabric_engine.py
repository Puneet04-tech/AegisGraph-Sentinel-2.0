"""
Data Fabric Engine.

Core engine for security data fabric operations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    DataAsset,
    DataClassification,
    DataDomain,
    DataSchema,
    DataCatalogEntry,
)
from .store import SecurityDataFabricStore, get_fabric_store


class DataFabricEngine:
    """Core engine for security data fabric."""

    def __init__(self, store: Optional[SecurityDataFabricStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_fabric_store()

    async def register_asset(
        self,
        name: str,
        description: str,
        domain: str,
        classification: str = "internal",
        schema_id: Optional[str] = None,
        source_system: Optional[str] = None,
        owner: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Register a new data asset."""
        asset_id = f"asset-{uuid.uuid4().hex[:12]}"
        
        domain_enum = DataDomain(domain)
        classification_enum = DataClassification(classification)
        
        asset = DataAsset(
            asset_id=asset_id,
            name=name,
            description=description,
            domain=domain_enum,
            schema_id=schema_id,
            classification=classification_enum,
            source_system=source_system,
            owner=owner,
            tags=tags or [],
        )
        
        self.store.register_asset(asset)
        
        catalog_entry = DataCatalogEntry(
            entry_id=f"cat-{uuid.uuid4().hex[:12]}",
            asset_id=asset_id,
            schema_id=schema_id or "",
            domain=domain_enum,
            classification=classification_enum,
            description=description,
            tags=tags or [],
            technical_owner=owner,
        )
        self.store.add_catalog_entry(catalog_entry)
        
        return {
            "asset_id": asset_id,
            "catalog_entry_id": catalog_entry.entry_id,
            "status": "registered",
            "domain": domain,
            "classification": classification,
        }

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Get asset details."""
        asset = self.store.get_asset(asset_id)
        if not asset:
            return None
        
        return self._asset_to_dict(asset)

    def _asset_to_dict(self, asset: DataAsset) -> Dict[str, Any]:
        """Convert asset to dictionary."""
        return {
            "asset_id": asset.asset_id,
            "name": asset.name,
            "description": asset.description,
            "domain": asset.domain.value,
            "classification": asset.classification.value,
            "schema_id": asset.schema_id,
            "source_system": asset.source_system,
            "owner": asset.owner,
            "tags": asset.tags,
            "row_count": asset.row_count,
            "size_bytes": asset.size_bytes,
            "created_at": asset.created_at.isoformat(),
            "updated_at": asset.updated_at.isoformat(),
        }

    def update_asset(
        self,
        asset_id: str,
        row_count: Optional[int] = None,
        size_bytes: Optional[int] = None,
        tags: Optional[List[str]] = None,
    ) -> bool:
        """Update an asset."""
        asset = self.store.get_asset(asset_id)
        if not asset:
            return False
        
        if row_count is not None:
            asset.row_count = row_count
        if size_bytes is not None:
            asset.size_bytes = size_bytes
        if tags is not None:
            asset.tags = tags
        
        asset.updated_at = datetime.now(timezone.utc)
        return True

    def register_schema(
        self,
        name: str,
        version: str,
        domain: str,
        fields: List[Dict[str, Any]],
        classification: str = "internal",
    ) -> Dict[str, Any]:
        """Register a data schema."""
        schema_id = f"schema-{uuid.uuid4().hex[:12]}"
        
        schema = DataSchema(
            schema_id=schema_id,
            name=name,
            version=version,
            domain=DataDomain(domain),
            fields=fields,
            classification=DataClassification(classification),
        )
        
        self.store.register_schema(schema)
        
        return {
            "schema_id": schema_id,
            "name": name,
            "version": version,
            "status": "registered",
        }

    def get_schema(self, schema_id: str) -> Optional[Dict[str, Any]]:
        """Get schema details."""
        schema = self.store.get_schema(schema_id)
        if not schema:
            return None
        
        return {
            "schema_id": schema.schema_id,
            "name": schema.name,
            "version": schema.version,
            "domain": schema.domain.value,
            "fields": schema.fields,
            "classification": schema.classification.value,
            "created_at": schema.created_at.isoformat(),
        }

    def get_assets(
        self,
        domain: Optional[str] = None,
        classification: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get assets with optional filtering."""
        assets = list(self.store._assets.values())
        
        if domain:
            domain_enum = DataDomain(domain)
            assets = [a for a in assets if a.domain == domain_enum]
        
        if classification:
            class_enum = DataClassification(classification)
            assets = [a for a in assets if a.classification == class_enum]
        
        assets.sort(key=lambda a: a.updated_at, reverse=True)
        return [self._asset_to_dict(a) for a in assets[:limit]]

    def get_fabric_dashboard(self) -> Dict[str, Any]:
        """Get fabric dashboard metrics."""
        metrics = self.store.get_fabric_metrics()
        schemas = list(self.store._schemas.values())
        policies = list(self.store._policies.values())
        
        return {
            **metrics,
            "schema_count": len(schemas),
            "policy_count": len(policies),
            "domains": list(DataDomain),
            "classifications": list(DataClassification),
        }


# Singleton instance
_engine: Optional[DataFabricEngine] = None


def get_fabric_engine() -> DataFabricEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = DataFabricEngine()
    return _engine


def reset_fabric_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None