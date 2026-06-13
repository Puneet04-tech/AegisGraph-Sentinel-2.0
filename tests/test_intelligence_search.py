"""Tests for Security Intelligence Search Engine"""

import pytest

from src.intelligence_search.models import SearchQuery, SearchResult
from src.intelligence_search.store import get_intelligence_search_store, reset_intelligence_search_store
from src.intelligence_search.service import IntelligenceSearchService


class TestIntelligenceSearchModels:
    def test_create_query(self):
        q = SearchQuery(query="ransomware attack patterns")
        assert q.query == "ransomware attack patterns"
        assert q.search_type == "SEMANTIC"

    def test_create_result(self):
        r = SearchResult(
            query_id="q-001", entity_type="threat", entity_id="t-001",
            title="Ransomware Variant X", description="New ransomware",
        )
        assert r.entity_type == "threat"


class TestIntelligenceSearchStore:
    def setup_method(self):
        reset_intelligence_search_store()
        self.store = get_intelligence_search_store()

    def test_store_query(self):
        q = SearchQuery(query="test query")
        self.store.store_query(q)
        assert self.store.get_query(q.query_id) is not None


class TestIntelligenceSearchService:
    def setup_method(self):
        reset_intelligence_search_store()
        self.service = IntelligenceSearchService()

    def test_search(self):
        q = self.service.search("fraud patterns")
        assert q.query_id is not None

    def test_add_result(self):
        q = self.service.search("test")
        r = self.service.add_result(q.query_id, "case", "c-001", "Test Case", "Description")
        assert r.result_id is not None

    def test_index_content(self):
        e = self.service.index_content("investigation", "inv-001", "Suspicious activity detected")
        assert e.entry_id is not None

    def test_get_metrics(self):
        self.service.search("test query")
        m = self.service.get_metrics()
        assert m.total_queries >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
