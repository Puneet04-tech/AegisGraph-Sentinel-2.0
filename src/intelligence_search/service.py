"""Security Intelligence Search Engine Service"""

from __future__ import annotations

from typing import List, Optional  # noqa: F401

from .models import SearchQuery, SearchResult, IndexEntry, SearchAnalytics
from .store import get_intelligence_search_store, IntelligenceSearchStore, reset_intelligence_search_store


class IntelligenceSearchService:
    """Core intelligence search service."""

    def __init__(self, store: Optional[IntelligenceSearchStore] = None):
        self._store = store or get_intelligence_search_store()

    def search(self, query: str, search_type: str = "SEMANTIC") -> SearchQuery:
        q = SearchQuery(query=query, search_type=search_type)
        self._store.store_query(q)
        return q

    def get_query(self, query_id: str) -> Optional[SearchQuery]:
        return self._store.get_query(query_id)

    def add_result(
        self, query_id: str, entity_type: str, entity_id: str,
        title: str, description: str,
    ) -> SearchResult:
        r = SearchResult(
            query_id=query_id, entity_type=entity_type, entity_id=entity_id,
            title=title, description=description, relevance_score=0.8,
        )
        self._store.store_result(r)
        return r

    def index_content(
        self, entity_type: str, entity_id: str, content: str,
    ) -> IndexEntry:
        e = IndexEntry(entity_type=entity_type, entity_id=entity_id, content=content)
        self._store.store_entry(e)
        return e

    def get_metrics(self) -> SearchAnalytics:
        m = self._store.get_metrics()
        return SearchAnalytics(total_queries=m["total_queries"])


_intelligence_search_service: Optional[IntelligenceSearchService] = None


def get_intelligence_search_service() -> IntelligenceSearchService:
    global _intelligence_search_service
    if _intelligence_search_service is None:
        _intelligence_search_service = IntelligenceSearchService()
    return _intelligence_search_service


def reset_intelligence_search_service() -> None:
    global _intelligence_search_service
    _intelligence_search_service = None
    reset_intelligence_search_store()
