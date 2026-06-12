"""
Security Data Fabric Store.

Storage layer for data fabric components.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    DataAsset,
    DataCatalogEntry,
    DataClassification,
    DataDomain,
    DataPolicy,
    DataQualityReport,
    DataSchema,
    LineageRecord,
    LineageType,
    QueryResult,
)


class SecurityDataFabricStore:
    """Store for security data fabric."""

    def __init__(self) -> None:
        """Initialize the store."""
        self._assets: Dict[str, DataAsset] = {}
        self._schemas: Dict[str, DataSchema] = {}
        self._catalog: Dict[str, DataCatalogEntry] = {}
        self._lineage: Dict[str, LineageRecord] = {}
        self._policies: Dict[str, DataPolicy] = {}
        self._quality_reports: Dict[str, DataQualityReport] = {}
        self._query_cache: Dict[str, QueryResult] = {}
        self._lock = threading.RLock()

    def register_asset(self, asset: DataAsset) -> None:
        """Register a data asset."""
        with self._lock:
            self._assets[asset.asset_id] = asset

    def get_asset(self, asset_id: str) -> Optional[DataAsset]:
        """Get an asset by ID."""
        return self._assets.get(asset_id)

    def get_assets_by_domain(self, domain: DataDomain) -> List[DataAsset]:
        """Get assets by domain."""
        return [a for a in self._assets.values() if a.domain == domain]

    def get_assets_by_classification(
        self,
        classification: DataClassification,
    ) -> List[DataAsset]:
        """Get assets by classification."""
        return [a for a in self._assets.values() if a.classification == classification]

    def register_schema(self, schema: DataSchema) -> None:
        """Register a schema."""
        with self._lock:
            self._schemas[schema.schema_id] = schema

    def get_schema(self, schema_id: str) -> Optional[DataSchema]:
        """Get a schema by ID."""
        return self._schemas.get(schema_id)

    def add_catalog_entry(self, entry: DataCatalogEntry) -> None:
        """Add a catalog entry."""
        with self._lock:
            self._catalog[entry.entry_id] = entry

    def get_catalog_entry(self, entry_id: str) -> Optional[DataCatalogEntry]:
        """Get a catalog entry by ID."""
        return self._catalog.get(entry_id)

    def get_catalog_by_domain(self, domain: DataDomain) -> List[DataCatalogEntry]:
        """Get catalog entries by domain."""
        return [e for e in self._catalog.values() if e.domain == domain]

    def search_catalog(self, query: str) -> List[DataCatalogEntry]:
        """Search catalog by query string."""
        results = []
        query_lower = query.lower()
        for entry in self._catalog.values():
            if query_lower in entry.asset_id.lower():
                results.append(entry)
            elif query_lower in entry.description.lower():
                results.append(entry)
            elif any(query_lower in tag.lower() for tag in entry.tags):
                results.append(entry)
        return results

    def add_lineage(self, record: LineageRecord) -> None:
        """Add a lineage record."""
        with self._lock:
            self._lineage[record.record_id] = record

    def get_lineage_for_asset(self, asset_id: str) -> List[LineageRecord]:
        """Get lineage for an asset."""
        return [
            r for r in self._lineage.values()
            if r.source_asset_id == asset_id or r.target_asset_id == asset_id
        ]

    def add_policy(self, policy: DataPolicy) -> None:
        """Add a data policy."""
        with self._lock:
            self._policies[policy.policy_id] = policy

    def get_policy(self, policy_id: str) -> Optional[DataPolicy]:
        """Get a policy by ID."""
        return self._policies.get(policy_id)

    def get_policies_by_domain(self, domain: DataDomain) -> List[DataPolicy]:
        """Get policies by domain."""
        return [p for p in self._policies.values() if p.domain == domain]

    def add_quality_report(self, report: DataQualityReport) -> None:
        """Add a quality report."""
        with self._lock:
            self._quality_reports[report.report_id] = report

    def get_quality_report(self, report_id: str) -> Optional[DataQualityReport]:
        """Get a quality report by ID."""
        return self._quality_reports.get(report_id)

    def get_latest_quality_report(self, asset_id: str) -> Optional[DataQualityReport]:
        """Get the latest quality report for an asset."""
        reports = [
            r for r in self._quality_reports.values()
            if r.asset_id == asset_id
        ]
        if not reports:
            return None
        return max(reports, key=lambda r: r.generated_at)

    def cache_query_result(self, query_id: str, result: QueryResult) -> None:
        """Cache a query result."""
        with self._lock:
            self._query_cache[query_id] = result

    def get_cached_result(self, query_id: str) -> Optional[QueryResult]:
        """Get a cached query result."""
        return self._query_cache.get(query_id)

    def get_fabric_metrics(self) -> Dict[str, Any]:
        """Get fabric metrics."""
        assets = list(self._assets.values())
        return {
            "total_assets": len(assets),
            "assets_by_domain": {
                d.value: len([a for a in assets if a.domain == d])
                for d in DataDomain
            },
            "assets_by_classification": {
                c.value: len([a for a in assets if a.classification == c])
                for c in DataClassification
            },
            "total_schemas": len(self._schemas),
            "total_catalog_entries": len(self._catalog),
            "total_lineage_records": len(self._lineage),
            "total_policies": len(self._policies),
            "cached_queries": len(self._query_cache),
        }

    def clear(self) -> None:
        """Clear all data."""
        with self._lock:
            self._assets.clear()
            self._schemas.clear()
            self._catalog.clear()
            self._lineage.clear()
            self._policies.clear()
            self._quality_reports.clear()
            self._query_cache.clear()


# Singleton instance
_store: Optional[SecurityDataFabricStore] = None
_store_lock = threading.Lock()


def get_fabric_store() -> SecurityDataFabricStore:
    """Get the global store instance."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = SecurityDataFabricStore()
    return _store


def reset_fabric_store() -> None:
    """Reset the global store."""
    global _store
    with _store_lock:
        if _store is not None:
            _store.clear()
        _store = None