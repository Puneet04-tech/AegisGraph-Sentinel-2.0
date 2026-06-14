"""Security Intelligence Search Engine Store"""

from __future__ import annotations

from threading import Lock
from typing import Any, Dict, Optional

from .models import SearchQuery, SearchResult, IndexEntry, SearchRanking


class IntelligenceSearchStore:
    """Thread-safe storage."""

    def __init__(self):
        self._lock = Lock()
        self._queries: Dict[str, SearchQuery] = {}
        self._results: Dict[str, SearchResult] = {}
        self._entries: Dict[str, IndexEntry] = {}
        self._rankings: Dict[str, SearchRanking] = {}

    def store_query(self, q: SearchQuery) -> SearchQuery:
        with self._lock:
            self._queries[q.query_id] = q
        return q

    def get_query(self, query_id: str) -> Optional[SearchQuery]:
        return self._queries.get(query_id)

    def store_result(self, r: SearchResult) -> SearchResult:
        with self._lock:
            self._results[r.result_id] = r
        return r

    def get_result(self, result_id: str) -> Optional[SearchResult]:
        return self._results.get(result_id)

    def store_entry(self, e: IndexEntry) -> IndexEntry:
        with self._lock:
            self._entries[e.entry_id] = e
        return e

    def get_entry(self, entry_id: str) -> Optional[IndexEntry]:
        return self._entries.get(entry_id)

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_queries": len(self._queries),
            "total_results": len(self._results),
            "indexed_entries": len(self._entries),
        }


_intelligence_search_store: Optional[IntelligenceSearchStore] = None
_store_lock = Lock()


def get_intelligence_search_store() -> IntelligenceSearchStore:
    global _intelligence_search_store
    with _store_lock:
        if _intelligence_search_store is None:
            _intelligence_search_store = IntelligenceSearchStore()
        return _intelligence_search_store


def reset_intelligence_search_store() -> None:
    global _intelligence_search_store
    with _store_lock:
        _intelligence_search_store = IntelligenceSearchStore()
