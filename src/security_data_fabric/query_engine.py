"""
Federated Query Engine.

Executes queries across multiple data domains.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import DataAsset, DataDomain, QueryRequest, QueryResult
from .store import SecurityDataFabricStore, get_fabric_store


class QueryEngine:
    """Engine for federated queries across domains."""

    def __init__(self, store: Optional[SecurityDataFabricStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_fabric_store()

    async def execute_query(
        self,
        query_string: str,
        domains: Optional[List[str]] = None,
        classification: Optional[str] = None,
        limit: int = 100,
        timeout_seconds: int = 30,
    ) -> QueryResult:
        """Execute a federated query."""
        query_id = f"q-{uuid.uuid4().hex[:12]}"
        
        if domains is None:
            domains = [d.value for d in DataDomain]
        
        start_time = datetime.now(timezone.utc)
        results: List[Dict[str, Any]] = []
        sources_queried: List[str] = []
        
        for domain_str in domains:
            domain = DataDomain(domain_str)
            assets = self.store.get_assets_by_domain(domain)
            
            if classification:
                class_enum = self._get_classification(classification)
                if class_enum:
                    assets = [a for a in assets if a.classification == class_enum]
            
            for asset in assets:
                if len(results) >= limit:
                    break
                
                sources_queried.append(asset.asset_id)
                
                if self._matches_query(asset, query_string):
                    results.append({
                        "asset_id": asset.asset_id,
                        "name": asset.name,
                        "domain": asset.domain.value,
                        "classification": asset.classification.value,
                        "tags": asset.tags,
                        "source_system": asset.source_system,
                        "row_count": asset.row_count,
                        "relevance_score": self._calculate_relevance(asset, query_string),
                    })
        
        results.sort(key=lambda x: x["relevance_score"], reverse=True)
        results = results[:limit]
        
        end_time = datetime.now(timezone.utc)
        execution_time = (end_time - start_time).total_seconds() * 1000
        
        result = QueryResult(
            result_id=str(uuid.uuid4()),
            query_id=query_id,
            data=results,
            row_count=len(results),
            execution_time_ms=execution_time,
            sources_queried=sources_queried,
            cached=False,
        )
        
        return result

    def _get_classification(self, classification: str) -> Optional[Any]:
        """Get classification enum."""
        from .models import DataClassification
        try:
            return DataClassification(classification)
        except ValueError:
            return None

    def _matches_query(self, asset: DataAsset, query_string: str) -> bool:
        """Check if asset matches query."""
        query_lower = query_string.lower()
        
        if query_lower in asset.name.lower():
            return True
        if query_lower in asset.description.lower():
            return True
        if query_lower in asset.asset_id.lower():
            return True
        if any(query_lower in tag.lower() for tag in asset.tags):
            return True
        
        return False

    def _calculate_relevance(self, asset: DataAsset, query_string: str) -> float:
        """Calculate relevance score for an asset."""
        score = 0.0
        query_lower = query_string.lower()
        
        if query_lower in asset.name.lower():
            score += 0.5
        if query_lower in asset.description.lower():
            score += 0.3
        if query_lower in asset.asset_id.lower():
            score += 0.2
        if any(query_lower in tag.lower() for tag in asset.tags):
            score += 0.2
        
        return min(1.0, score)

    def cache_result(self, query_id: str, result: QueryResult) -> None:
        """Cache a query result."""
        self.store.cache_query_result(query_id, result)

    def get_cached_result(self, query_id: str) -> Optional[QueryResult]:
        """Get a cached query result."""
        return self.store.get_cached_result(query_id)


# Singleton instance
_engine: Optional[QueryEngine] = None


def get_query_engine() -> QueryEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = QueryEngine()
    return _engine


def reset_query_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None