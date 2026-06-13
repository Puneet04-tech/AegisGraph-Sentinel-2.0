"""
Comprehensive tests for case embeddings, vector store, and retrieval system.

Tests:
- VectorStore: Add, query, batch operations, LRU eviction
- CaseEmbedder: Embedding generation, caching, fallback
- CaseRetriever: Indexing, finding similar, metadata updates
- API integration

Coverage target: >80% of new RAG code
"""

import pytest
import numpy as np
from typing import Dict, List
import time

from src.case_management.vector_store import VectorStore, SearchResult
from src.embeddings import CaseEmbedder, get_embedder
from src.case_management.retriever import CaseRetriever


# =============================================================================
# VECTOR STORE TESTS
# =============================================================================

class TestVectorStore:
    """Test suite for VectorStore (low-level vector similarity search)."""
    
    @pytest.fixture
    def store(self):
        """Create a fresh VectorStore for each test."""
        return VectorStore(embedding_dim=768, maxsize=100, similarity_threshold=0.5)
    
    @pytest.fixture
    def sample_embedding(self):
        """Generate a sample embedding."""
        return np.random.randn(768).astype(np.float32)
    
    def test_add_single_embedding(self, store, sample_embedding):
        """Test adding a single embedding to the store."""
        store.add(
            case_id="CASE_001",
            embedding=sample_embedding,
            metadata={"priority": "HIGH", "date": "2026-06-10"}
        )
        
        # Verify it was added
        result = store.get("CASE_001")
        assert result is not None
        embedding, metadata = result
        assert metadata["priority"] == "HIGH"
        assert metadata["date"] == "2026-06-10"
    
    def test_add_overwrites_existing(self, store, sample_embedding):
        """Test that adding with same case_id overwrites."""
        store.add("CASE_001", sample_embedding, {"version": "1"})
        store.add("CASE_001", sample_embedding, {"version": "2"})
        
        _, metadata = store.get("CASE_001")
        assert metadata["version"] == "2"
    
    def test_query_returns_top_k(self, store):
        """Test that query returns exactly k results."""
        embeddings = [np.random.randn(768).astype(np.float32) for _ in range(20)]
        for i, emb in enumerate(embeddings):
            store.add(f"CASE_{i}", emb, {"index": i})
        
        # Query with first embedding
        results = store.query(embeddings[0], k=5)
        assert len(results) <= 5
        assert results[0].case_id == "CASE_0"  # First should be itself
    
    def test_query_with_threshold(self, store):
        """Test that threshold filters low-similarity results."""
        embeddings = [np.random.randn(768).astype(np.float32) for _ in range(10)]
        for i, emb in enumerate(embeddings):
            store.add(f"CASE_{i}", emb, {})
        
        # Query with high threshold (should get few results)
        results = store.query(embeddings[0], k=10, threshold=0.95)
        # Results should only include very similar ones
        assert all(r.similarity_score >= 0.95 for r in results)
    
    def test_batch_add(self, store):
        """Test batch adding embeddings."""
        embeddings = np.array([np.random.randn(768).astype(np.float32) for _ in range(5)])
        case_ids = [f"CASE_{i}" for i in range(5)]
        metadatas = [{"index": i} for i in range(5)]
        
        store.add_batch(case_ids, embeddings, metadatas)
        
        # Verify all were added
        for case_id in case_ids:
            assert store.get(case_id) is not None
    
    def test_batch_query(self, store):
        """Test querying multiple embeddings at once."""
        embeddings = np.array([np.random.randn(768).astype(np.float32) for _ in range(10)])
        for i, emb in enumerate(embeddings):
            store.add(f"CASE_{i}", emb, {})
        
        query_embeddings = embeddings[:3]
        results = store.query_batch(query_embeddings, k=5)
        
        assert len(results) == 3  # One result list per query
        assert all(len(r) <= 5 for r in results)  # Each result list has at most k
    
    def test_lru_eviction(self):
        """Test LRU eviction when maxsize exceeded."""
        store = VectorStore(embedding_dim=768, maxsize=5, similarity_threshold=0.5)
        embeddings = [np.random.randn(768).astype(np.float32) for _ in range(10)]
        
        # Add 10 embeddings to store with maxsize=5
        for i, emb in enumerate(embeddings):
            store.add(f"CASE_{i}", emb, {})
        
        # Check that only 5 remain
        stats = store.get_stats()
        assert stats["total_cases"] == 5
        
        # First 5 should be evicted (oldest)
        for i in range(5):
            assert store.get(f"CASE_{i}") is None
        
        # Last 5 should remain
        for i in range(5, 10):
            assert store.get(f"CASE_{i}") is not None
    
    def test_remove_case(self, store, sample_embedding):
        """Test removing a case from the store."""
        store.add("CASE_001", sample_embedding, {})
        assert store.get("CASE_001") is not None
        
        removed = store.remove("CASE_001")
        assert removed is True
        assert store.get("CASE_001") is None
    
    def test_remove_nonexistent_case(self, store):
        """Test removing a non-existent case."""
        removed = store.remove("NONEXISTENT")
        assert removed is False
    
    def test_update_metadata(self, store, sample_embedding):
        """Test updating metadata without re-embedding."""
        store.add("CASE_001", sample_embedding, {"priority": "LOW"})
        
        updated = store.update_metadata("CASE_001", {"priority": "HIGH"})
        assert updated is True
        
        _, metadata = store.get("CASE_001")
        assert metadata["priority"] == "HIGH"
    
    def test_get_stats(self, store):
        """Test retrieving statistics."""
        embeddings = np.array([np.random.randn(768).astype(np.float32) for _ in range(5)])
        for i, emb in enumerate(embeddings):
            store.add(f"CASE_{i}", emb, {})
        
        stats = store.get_stats()
        assert stats["total_added"] == 5
        assert stats["current_size"] == 5
        assert stats["max_size"] == 100
    
    def test_clear_store(self, store, sample_embedding):
        """Test clearing all cases."""
        store.add("CASE_001", sample_embedding, {})
        store.add("CASE_002", sample_embedding, {})
        
        store.clear()
        
        stats = store.get_stats()
        assert stats["current_size"] == 0
    
    def test_cosine_similarity_range(self, store):
        """Test that similarity scores are in [0, 1] range."""
        embeddings = [np.random.randn(768).astype(np.float32) for _ in range(5)]
        for i, emb in enumerate(embeddings):
            store.add(f"CASE_{i}", emb, {})
        
        results = store.query(embeddings[0], k=5)
        for r in results:
            assert 0.0 <= r.similarity_score <= 1.0


# =============================================================================
# CASE EMBEDDER TESTS
# =============================================================================

class TestCaseEmbedder:
    """Test suite for CaseEmbedder (semantic embeddings)."""
    
    @pytest.fixture
    def embedder(self):
        """Create a CaseEmbedder instance."""
        return CaseEmbedder(embedding_dim=768)
    
    def test_embed_text(self, embedder):
        """Test embedding a text string."""
        text = "Suspicious transfer to new recipient detected"
        embedding = embedder.embed_text(text)
        
        assert isinstance(embedding, np.ndarray)
        assert embedding.shape == (768,)
        assert embedding.dtype == np.float32
    
    def test_embedding_deterministic_with_fallback(self, embedder):
        """Test that mock embeddings are deterministic."""
        text = "Test fraud case"
        
        emb1 = embedder.embed_text(text)
        emb2 = embedder.embed_text(text)
        
        # Should be identical (either from cache or mock deterministic)
        np.testing.assert_array_equal(emb1, emb2)
    
    def test_embed_batch(self, embedder):
        """Test embedding multiple texts at once."""
        texts = [
            "Fraud case 1: Suspicious transfer",
            "Fraud case 2: Multiple accounts",
            "Fraud case 3: High-value transaction"
        ]
        
        embeddings = embedder.embed_batch(texts)
        
        assert len(embeddings) == 3
        assert all(e.shape == (768,) for e in embeddings)
    
    def test_embed_case_explanation(self, embedder):
        """Test embedding a fraud explanation dict."""
        explanation = {
            "summary": "Mule account detected",
            "explanation": "Account A transferred to account B with suspicious pattern",
            "factors": {
                "velocity": 0.9,
                "graph": 0.85,
                "behavior": 0.88
            }
        }
        
        embedding = embedder.embed_case_explanation(explanation)
        
        assert isinstance(embedding, np.ndarray)
        assert embedding.shape == (768,)
    
    def test_caching(self, embedder):
        """Test that embeddings are cached."""
        text = "Test text for caching"
        
        # First embedding
        emb1 = embedder.embed_text(text)
        initial_cache_size = embedder.get_cache_stats()["cached_embeddings"]
        
        # Second embedding (should hit cache)
        emb2 = embedder.embed_text(text)
        
        # Should be identical
        np.testing.assert_array_equal(emb1, emb2)
        # Cache size should remain the same (cache hit)
        new_cache_size = embedder.get_cache_stats()["cached_embeddings"]
        assert new_cache_size == initial_cache_size
    
    def test_text_truncation(self, embedder):
        """Test that long texts are truncated."""
        # Create a very long text (>10000 chars)
        long_text = "A" * 20000
        
        # Should not raise an error
        embedding = embedder.embed_text(long_text)
        assert embedding.shape == (768,)
    
    def test_get_cache_stats(self, embedder):
        """Test retrieving cache statistics."""
        embedder.embed_text("Test 1")
        embedder.embed_text("Test 2")
        embedder.embed_text("Test 1")  # Cache hit
        
        stats = embedder.get_cache_stats()
        assert stats["cached_embeddings"] >= 2
        assert "cache_enabled" in stats
    
    def test_clear_cache(self, embedder):
        """Test clearing the embedding cache."""
        embedder.embed_text("Test text")
        initial_size = embedder.get_cache_stats()["cache_size"]
        assert initial_size > 0
        
        embedder.clear_cache()
        
        new_size = embedder.get_cache_stats()["cache_size"]
        assert new_size == 0
    
    def test_get_embedder_singleton(self):
        """Test that get_embedder returns same instance."""
        embedder1 = get_embedder(embedding_dim=768)
        embedder2 = get_embedder(embedding_dim=768)
        
        # Should be same instance (singleton)
        assert embedder1 is embedder2


# =============================================================================
# CASE RETRIEVER TESTS
# =============================================================================

class TestCaseRetriever:
    """Test suite for CaseRetriever (high-level semantic search API)."""
    
    @pytest.fixture
    def retriever(self):
        """Create a fresh CaseRetriever for testing."""
        return CaseRetriever(embedding_dim=768)
    
    @pytest.fixture
    def sample_cases(self):
        """Generate sample fraud cases."""
        return [
            {
                "case_id": "CASE_001",
                "explanation": {
                    "summary": "Mule account detected",
                    "explanation": "Account transferred to multiple new recipients"
                },
                "metadata": {"priority": "HIGH", "date": "2026-06-01"}
            },
            {
                "case_id": "CASE_002",
                "explanation": {
                    "summary": "High-value transfer",
                    "explanation": "Sudden large transfer to overseas account"
                },
                "metadata": {"priority": "MEDIUM", "date": "2026-06-05"}
            },
            {
                "case_id": "CASE_003",
                "explanation": {
                    "summary": "Velocity spike",
                    "explanation": "Multiple rapid transfers within minutes"
                },
                "metadata": {"priority": "HIGH", "date": "2026-06-08"}
            }
        ]
    
    def test_index_single_case(self, retriever, sample_cases):
        """Test indexing a single case."""
        case = sample_cases[0]
        retriever.index_case(
            case_id=case["case_id"],
            explanation=case["explanation"],
            metadata=case["metadata"]
        )
        
        stats = retriever.get_stats()
        assert stats["vector_store"]["total_cases"] == 1
    
    def test_batch_index_cases(self, retriever, sample_cases):
        """Test batch indexing multiple cases."""
        retriever.index_cases_batch(sample_cases)
        
        stats = retriever.get_stats()
        assert stats["vector_store"]["total_cases"] == 3
    
    def test_find_similar_by_text(self, retriever, sample_cases):
        """Test finding similar cases by text query."""
        retriever.index_cases_batch(sample_cases)
        
        results = retriever.find_similar(
            query_text="Multiple recipients transferring funds",
            k=2
        )
        
        assert len(results) <= 2
        assert all("case_id" in r for r in results)
        assert all("similarity" in r for r in results)
        assert all("similarity_percent" in r for r in results)
        assert all(0.0 <= r["similarity"] <= 1.0 for r in results)
    
    def test_find_similar_by_case_id(self, retriever, sample_cases):
        """Test finding cases similar to an existing case."""
        retriever.index_cases_batch(sample_cases)
        
        results = retriever.find_similar_by_case(
            case_id="CASE_001",
            k=2,
            exclude_self=True
        )
        
        # Should not include CASE_001 itself
        assert all(r["case_id"] != "CASE_001" for r in results)
        assert len(results) <= 2
    
    def test_find_similar_excludes_self(self, retriever, sample_cases):
        """Test that find_similar_by_case excludes self when requested."""
        retriever.index_cases_batch(sample_cases)
        
        results_with_self = retriever.find_similar_by_case(
            case_id="CASE_001",
            k=3,
            exclude_self=False
        )
        
        results_without_self = retriever.find_similar_by_case(
            case_id="CASE_001",
            k=3,
            exclude_self=True
        )
        
        # Without self should have fewer or equal results
        assert len(results_without_self) <= len(results_with_self)
        
        # Without self should not have CASE_001
        assert all(r["case_id"] != "CASE_001" for r in results_without_self)
    
    def test_find_similar_by_explanation(self, retriever, sample_cases):
        """Test finding similar cases by explanation dict."""
        retriever.index_cases_batch(sample_cases)
        
        query_explanation = {
            "summary": "Similar mule pattern",
            "explanation": "Multiple accounts involved in transfers"
        }
        
        results = retriever.find_similar_by_explanation(
            explanation=query_explanation,
            k=2
        )
        
        assert len(results) <= 2
        assert all("case_id" in r for r in results)
    
    def test_update_case_metadata(self, retriever, sample_cases):
        """Test updating metadata for an indexed case."""
        retriever.index_case(
            case_id=sample_cases[0]["case_id"],
            explanation=sample_cases[0]["explanation"],
            metadata=sample_cases[0]["metadata"]
        )
        
        updated = retriever.update_case_metadata(
            case_id=sample_cases[0]["case_id"],
            metadata={"status": "RESOLVED", "priority": "CRITICAL"}
        )
        
        assert updated is True
    
    def test_remove_case(self, retriever, sample_cases):
        """Test removing a case from the index."""
        retriever.index_case(
            case_id=sample_cases[0]["case_id"],
            explanation=sample_cases[0]["explanation"],
            metadata=sample_cases[0]["metadata"]
        )
        
        removed = retriever.remove_case(sample_cases[0]["case_id"])
        assert removed is True
        
        stats = retriever.get_stats()
        assert stats["vector_store"]["total_cases"] == 0
    
    def test_get_stats(self, retriever, sample_cases):
        """Test retrieving system statistics."""
        retriever.index_cases_batch(sample_cases)
        
        stats = retriever.get_stats()
        assert "vector_store" in stats
        assert "embedder_cache" in stats
        assert stats["vector_store"]["total_cases"] == 3
    
    def test_clear_all(self, retriever, sample_cases):
        """Test clearing all indexed cases and caches."""
        retriever.index_cases_batch(sample_cases)
        assert retriever.get_stats()["vector_store"]["total_cases"] == 3
        
        retriever.clear_all()
        
        assert retriever.get_stats()["vector_store"]["total_cases"] == 0
        assert retriever.get_stats()["embedder_cache"]["cache_size"] == 0
    
    def test_similarity_ranking(self, retriever, sample_cases):
        """Test that results are ranked by similarity."""
        retriever.index_cases_batch(sample_cases)
        
        results = retriever.find_similar(
            query_text="Mule account transfers",
            k=10
        )
        
        # Results should be sorted by similarity (descending)
        similarities = [r["similarity"] for r in results]
        assert similarities == sorted(similarities, reverse=True)
    
    def test_similarity_percent_format(self, retriever, sample_cases):
        """Test that similarity_percent is properly formatted."""
        retriever.index_cases_batch(sample_cases)
        
        results = retriever.find_similar(
            query_text="Test query",
            k=5
        )
        
        for r in results:
            percent_str = r["similarity_percent"]
            assert "%" in percent_str
            # Should be able to extract a number
            num_str = percent_str.rstrip("%")
            float(num_str)  # Should not raise


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestRAGIntegration:
    """Integration tests for the full RAG system."""
    
    def test_full_workflow(self):
        """Test complete RAG workflow: index -> search -> retrieve."""
        retriever = CaseRetriever(embedding_dim=768)
        
        # Step 1: Index cases
        cases = [
            {
                "case_id": "CASE_A",
                "explanation": {
                    "summary": "Mule chain detected",
                    "explanation": "Account A → Account B → Account C pattern"
                },
                "metadata": {"priority": "CRITICAL"}
            },
            {
                "case_id": "CASE_B",
                "explanation": {
                    "summary": "Legitimate transfer",
                    "explanation": "Single transfer from trusted source"
                },
                "metadata": {"priority": "LOW"}
            }
        ]
        
        retriever.index_cases_batch(cases)
        
        # Step 2: Query for similar cases
        results = retriever.find_similar(
            query_text="Chain of suspicious transfers",
            k=5
        )
        
        # Step 3: Verify results
        assert len(results) > 0
        assert all("case_id" in r for r in results)
        assert all(0 <= r["similarity"] <= 1 for r in results)
    
    def test_error_handling(self):
        """Test error handling in retriever."""
        retriever = CaseRetriever(embedding_dim=768)
        
        # Find similar on empty index should return empty list
        results = retriever.find_similar(
            query_text="Test query",
            k=5
        )
        assert results == []
    
    def test_performance(self):
        """Test performance with multiple cases."""
        retriever = CaseRetriever(embedding_dim=768)
        
        # Index 100 cases
        cases = [
            {
                "case_id": f"CASE_{i:03d}",
                "explanation": {
                    "summary": f"Fraud case {i}",
                    "explanation": f"Description for case {i}"
                },
                "metadata": {"index": i}
            }
            for i in range(100)
        ]
        
        start = time.time()
        retriever.index_cases_batch(cases)
        index_time = time.time() - start
        
        # Search should be fast
        start = time.time()
        results = retriever.find_similar(
            query_text="Fraud pattern query",
            k=10
        )
        search_time = time.time() - start
        
        # Rough performance expectations (may vary)
        assert search_time < 1.0  # Should complete within 1 second
        assert len(results) <= 10
