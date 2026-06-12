"""
Metadata Catalog Service.

Manages the metadata catalog for data assets.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import DataCatalogEntry, DataClassification, DataDomain
from .store import SecurityDataFabricStore, get_fabric_store


class CatalogService:
    """Service for managing metadata catalog."""

    def __init__(self, store: Optional[SecurityDataFabricStore] = None) -> None:
        """Initialize the service."""
        self.store = store or get_fabric_store()

    def add_entry(
        self,
        asset_id: str,
        schema_id: str,
        domain: str,
        classification: str,
        description: str,
        tags: Optional[List[str]] = None,
        business_owner: Optional[str] = None,
        technical_owner: Optional[str] = None,
    ) -> DataCatalogEntry:
        """Add a catalog entry."""
        entry_id = f"cat-{uuid.uuid4().hex[:12]}"
        
        entry = DataCatalogEntry(
            entry_id=entry_id,
            asset_id=asset_id,
            schema_id=schema_id,
            domain=DataDomain(domain),
            classification=DataClassification(classification),
            description=description,
            tags=tags or [],
            business_owner=business_owner,
            technical_owner=technical_owner,
        )
        
        self.store.add_catalog_entry(entry)
        return entry

    def get_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        """Get a catalog entry."""
        entry = self.store.get_catalog_entry(entry_id)
        if not entry:
            return None
        
        return self._entry_to_dict(entry)

    def _entry_to_dict(self, entry: DataCatalogEntry) -> Dict[str, Any]:
        """Convert entry to dictionary."""
        return {
            "entry_id": entry.entry_id,
            "asset_id": entry.asset_id,
            "schema_id": entry.schema_id,
            "domain": entry.domain.value,
            "classification": entry.classification.value,
            "description": entry.description,
            "tags": entry.tags,
            "business_owner": entry.business_owner,
            "technical_owner": entry.technical_owner,
            "quality_score": entry.quality_score,
            "usage_count": entry.usage_count,
            "created_at": entry.created_at.isoformat(),
        }

    def search(self, query: str, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search the catalog."""
        entries = self.store.search_catalog(query)
        
        if domain:
            domain_enum = DataDomain(domain)
            entries = [e for e in entries if e.domain == domain_enum]
        
        return [self._entry_to_dict(e) for e in entries]

    def get_by_domain(self, domain: str) -> List[Dict[str, Any]]:
        """Get catalog entries by domain."""
        entries = self.store.get_catalog_by_domain(DataDomain(domain))
        return [self._entry_to_dict(e) for e in entries]

    def update_usage(self, entry_id: str) -> bool:
        """Update usage statistics for an entry."""
        entry = self.store.get_catalog_entry(entry_id)
        if not entry:
            return False
        
        entry.usage_count += 1
        entry.last_queried = datetime.now(timezone.utc)
        return True

    def update_quality_score(self, entry_id: str, score: float) -> bool:
        """Update quality score for an entry."""
        entry = self.store.get_catalog_entry(entry_id)
        if not entry:
            return False
        
        entry.quality_score = max(0.0, min(1.0, score))
        return True

    def get_catalog_stats(self) -> Dict[str, Any]:
        """Get catalog statistics."""
        entries = list(self.store._catalog.values())
        
        return {
            "total_entries": len(entries),
            "entries_by_domain": {
                d.value: len([e for e in entries if e.domain == d])
                for d in DataDomain
            },
            "entries_by_classification": {
                c.value: len([e for e in entries if e.classification == c])
                for c in DataClassification
            },
            "avg_quality_score": sum(e.quality_score for e in entries) / len(entries) if entries else 0,
            "total_usage": sum(e.usage_count for e in entries),
        }


# Singleton instance
_service: Optional[CatalogService] = None


def get_catalog_service() -> CatalogService:
    """Get the global service instance."""
    global _service
    if _service is None:
        _service = CatalogService()
    return _service


def reset_catalog_service() -> None:
    """Reset the global service."""
    global _service
    _service = None