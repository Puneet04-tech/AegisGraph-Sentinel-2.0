"""Unit tests for Graph Operation Caching Layer"""

import networkx as nx
import pytest
from unittest.mock import patch

from src.utils.cache import (
    GraphCache,
    GraphOperationCache,
    InMemoryGraphCache,
    RedisGraphCache,
    get_graph_cache,
    reset_cache,
)


class TestInMemoryGraphCache:
    """Test in-memory cache implementation"""

    @pytest.fixture
    def cache(self):
        return InMemoryGraphCache(max_size=10)

    def test_cache_set_and_get(self, cache):
        """Test basic set and get operations"""
        cache.set("key1", {"value": 123})
        assert cache.get("key1") == {"value": 123}

    def test_cache_get_missing_key(self, cache):
        """Test get returns None for missing keys"""
        assert cache.get("nonexistent") is None

    def test_cache_invalidate(self, cache):
        """Test cache invalidation"""
        cache.set("key1", "value1")
        cache.invalidate("key1")
        assert cache.get("key1") is None

    def test_cache_clear(self, cache):
        """Test cache clearing"""
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.clear()
        assert cache.get("key1") is None
        assert cache.get("key2") is None

    def test_cache_hit_rate(self, cache):
        """Test cache statistics"""
        cache.set("key1", "value1")
        
        # 3 hits
        cache.get("key1")
        cache.get("key1")
        cache.get("key1")
        
        # 2 misses
        cache.get("key2")
        cache.get("key3")
        
        stats = cache.get_stats()
        assert stats["hits"] == 3
        assert stats["misses"] == 2
        assert stats["total_requests"] == 5
        assert stats["hit_rate_percent"] == 60.0

    def test_cache_max_size_eviction(self, cache):
        """Test LRU-like eviction when max size exceeded"""
        for i in range(15):  # More than max_size=10
            cache.set(f"key{i}", f"value{i}")
        
        assert len(cache.cache) == 10  # Should evict oldest

    def test_cache_ttl_is_enforced_on_read(self, cache):
        """Test that expired entries are removed and missed on access."""
        with patch("src.utils.cache.time.time", side_effect=[100.0, 103.0]):
            cache.set("key1", "value1", ttl=2)
            assert cache.get("key1") is None
            assert "key1" not in cache.cache

    def test_cache_methods_use_lock(self, cache):
        """Test that core cache operations run under the shared lock."""

        class RecordingLock:
            def __init__(self):
                self.entered = 0
                self.exited = 0

            def __enter__(self):
                self.entered += 1
                return self

            def __exit__(self, exc_type, exc, tb):
                self.exited += 1
                return False

        lock = RecordingLock()
        cache._lock = lock

        cache.set("key1", "value1")
        cache.get("key1")
        cache.invalidate("key1")
        cache.clear()
        cache.get_stats()

        assert lock.entered == lock.exited
        assert lock.entered >= 5


class TestGraphOperationCache:
    """Test high-level graph operation caching"""

    @pytest.fixture
    def cache(self):
        """Create cache with in-memory backend"""
        reset_cache()
        return GraphOperationCache(backend=InMemoryGraphCache())

    @pytest.fixture
    def sample_graph(self):
        """Create sample directed graph for testing"""
        G = nx.DiGraph()
        G.add_weighted_edges_from(
            [
                ("A", "B", 100),
                ("B", "C", 150),
                ("C", "D", 200),
                ("D", "A", 120),
                ("B", "D", 180),
            ]
        )
        return G

    def test_graph_hash_is_deterministic(self, sample_graph):
        """Test that graph hash is consistent"""
        hash1 = GraphOperationCache._hash_graph(sample_graph)
        hash2 = GraphOperationCache._hash_graph(sample_graph)
        assert hash1 == hash2

    def test_different_graphs_have_different_hashes(self):
        """Test that different graphs produce different hashes"""
        G1 = nx.DiGraph()
        G1.add_edges_from([("A", "B"), ("B", "C")])
        
        G2 = nx.DiGraph()
        G2.add_edges_from([("A", "B"), ("B", "D")])
        
        hash1 = GraphOperationCache._hash_graph(G1)
        hash2 = GraphOperationCache._hash_graph(G2)
        assert hash1 != hash2

    def test_graph_hash_changes_when_edge_weight_changes(self):
        """Test that weighted edge changes invalidate the graph hash."""
        G1 = nx.DiGraph()
        G1.add_weighted_edges_from([("A", "B", 1.0)])
        G1["A"]["B"]["timestamp"] = 100.0

        G2 = nx.DiGraph()
        G2.add_weighted_edges_from([("A", "B", 2.0)])
        G2["A"]["B"]["timestamp"] = 100.0

        hash1 = GraphOperationCache._hash_graph(G1)
        hash2 = GraphOperationCache._hash_graph(G2)
        assert hash1 != hash2

    def test_graph_hash_changes_when_edge_metadata_changes(self):
        """Test that non-weight edge metadata also invalidates the graph hash."""
        G1 = nx.DiGraph()
        G1.add_weighted_edges_from([("A", "B", 1.0)])
        G1["A"]["B"]["timestamp"] = 100.0
        G1["A"]["B"]["channel"] = "card"

        G2 = nx.DiGraph()
        G2.add_weighted_edges_from([("A", "B", 1.0)])
        G2["A"]["B"]["timestamp"] = 100.0
        G2["A"]["B"]["channel"] = "wire"

        hash1 = GraphOperationCache._hash_graph(G1)
        hash2 = GraphOperationCache._hash_graph(G2)
        assert hash1 != hash2

    def test_cache_betweenness_centrality(self, cache, sample_graph):
        """Test caching of betweenness centrality"""
        # First call should compute
        result1 = cache.cache_betweenness_centrality(sample_graph, weight="weight")
        assert isinstance(result1, dict)
        assert all(isinstance(v, float) for v in result1.values())
        assert all(0 <= v <= 1 for v in result1.values())
        
        # Second call should be from cache
        result2 = cache.cache_betweenness_centrality(sample_graph, weight="weight")
        assert result1 == result2
        
        # Verify cache hit
        stats = cache.get_stats()
        assert stats["hits"] == 1

    def test_cache_pagerank(self, cache, sample_graph):
        """Test caching of PageRank"""
        # First call should compute
        result1 = cache.cache_pagerank(sample_graph, weight="weight")
        assert isinstance(result1, dict)
        assert all(isinstance(v, float) for v in result1.values())
        
        # Second call should be from cache
        result2 = cache.cache_pagerank(sample_graph, weight="weight")
        assert result1 == result2
        
        # Verify cache hit
        stats = cache.get_stats()
        assert stats["hits"] == 1

    def test_cache_find_cliques(self, cache):
        """Test caching of clique detection"""
        # Create an undirected graph with known cliques
        G = nx.Graph()
        # Complete triangle: A-B-C all connected
        G.add_edges_from([
            ("A", "B"), ("B", "C"), ("C", "A"),
            ("D", "E"),  # Another pair (2-clique)
        ])
        
        # First call should compute
        result1 = cache.cache_find_cliques(G)
        assert isinstance(result1, list)
        assert len(result1) >= 2  # At least the triangle and the pair
        
        # Second call should be from cache
        result2 = cache.cache_find_cliques(G)
        assert result1 == result2
        
        # Verify cache hit
        stats = cache.get_stats()
        assert stats["hits"] == 1

    def test_invalidate_graph(self, sample_graph):
        """Test graph invalidation"""
        # Create fresh cache
        cache = GraphOperationCache(backend=InMemoryGraphCache())
        
        # Populate cache
        cache.cache_betweenness_centrality(sample_graph)
        cache.cache_pagerank(sample_graph)
        
        stats_before = cache.get_stats()
        assert stats_before["hits"] == 0  # No hits, just 2 computations
        assert stats_before["misses"] == 2  # 2 misses (new calculations)
        
        # Recompute same operations - should get cache hits
        cache.cache_betweenness_centrality(sample_graph)
        cache.cache_pagerank(sample_graph)
        
        stats_after_recompute = cache.get_stats()
        assert stats_after_recompute["hits"] == 2  # 2 hits on second run
        
        # Invalidate
        cache.invalidate_graph(sample_graph)
        
        # Reset stats and verify cache cleared
        reset_cache()
        cache_new = GraphOperationCache(backend=InMemoryGraphCache())
        
        # First computation should be a miss
        result = cache_new.cache_betweenness_centrality(sample_graph)
        assert result is not None
        
        stats_new = cache_new.get_stats()
        assert stats_new["misses"] == 1

    def test_clear_cache(self, sample_graph):
        """Test cache clearing"""
        cache = GraphOperationCache(backend=InMemoryGraphCache())
        
        # Add entries
        cache.cache_betweenness_centrality(sample_graph)
        cache.cache_pagerank(sample_graph)
        
        # Recompute to get hits
        cache.cache_betweenness_centrality(sample_graph)
        cache.cache_pagerank(sample_graph)
        
        stats = cache.get_stats()
        assert stats["hits"] > 0  # Should have cache hits
        
        # Clear cache
        cache.clear()
        
        # Create new cache instance to verify previous is gone
        cache_new = GraphOperationCache(backend=InMemoryGraphCache())
        stats_new = cache_new.get_stats()
        assert stats_new["hits"] == 0  # New instance starts fresh

    def test_ttl_parameter(self, cache, sample_graph):
        """Test TTL parameter is passed correctly"""
        # Should not raise error
        result = cache.cache_betweenness_centrality(
            sample_graph, weight="weight", ttl=300
        )
        assert result is not None


class TestCacheIntegration:
    """Integration tests with actual graph operations"""

    def test_betweenness_centrality_correctness(self):
        """Verify cached results match non-cached"""
        G = nx.DiGraph()
        G.add_weighted_edges_from([
            ("A", "B", 100),
            ("B", "C", 100),
            ("C", "A", 100),
        ])
        
        cache = GraphOperationCache(backend=InMemoryGraphCache())
        
        # Compute via cache
        cached_result = cache.cache_betweenness_centrality(G, weight="weight")
        
        # Compute directly
        direct_result = nx.betweenness_centrality(G, normalized=True, weight="weight")
        
        # Should be approximately equal
        for node in G.nodes():
            assert abs(cached_result[node] - direct_result[node]) < 1e-6

    def test_pagerank_correctness(self):
        """Verify cached PageRank matches non-cached"""
        G = nx.DiGraph()
        G.add_weighted_edges_from([
            ("A", "B", 100),
            ("B", "C", 100),
            ("C", "D", 100),
            ("D", "A", 100),
        ])
        
        cache = GraphOperationCache(backend=InMemoryGraphCache())
        
        # Compute via cache
        cached_result = cache.cache_pagerank(G, alpha=0.85, weight="weight")
        
        # Compute directly
        direct_result = nx.pagerank(G, alpha=0.85, weight="weight")
        
        # Should be approximately equal
        for node in G.nodes():
            assert abs(cached_result[node] - direct_result[node]) < 1e-6

    def test_clique_detection_correctness(self):
        """Verify cached cliques match non-cached"""
        G = nx.Graph()
        # Create a complete graph with 4 nodes
        G.add_edges_from([
            ("A", "B"), ("A", "C"), ("A", "D"),
            ("B", "C"), ("B", "D"),
            ("C", "D"),
        ])
        
        cache = GraphOperationCache(backend=InMemoryGraphCache())
        
        # Compute via cache
        cached_cliques = cache.cache_find_cliques(G)
        
        # Compute directly
        direct_cliques = [frozenset(c) for c in nx.find_cliques(G)]
        
        # Should have same cliques
        assert len(cached_cliques) == len(direct_cliques)
        assert set(cached_cliques) == set(direct_cliques)


class TestGlobalCacheInstance:
    """Test global cache singleton"""

    def test_get_graph_cache_singleton(self):
        """Test that get_graph_cache returns singleton"""
        reset_cache()
        
        cache1 = get_graph_cache()
        cache2 = get_graph_cache()
        
        assert cache1 is cache2

    def test_reset_cache(self):
        """Test cache reset functionality"""
        cache1 = get_graph_cache()
        reset_cache()
        cache2 = get_graph_cache()
        
        assert cache1 is not cache2


class TestRedisGraphCache:
    """Test secure JSON serialization for Redis cache payloads."""

    @pytest.fixture
    def cache(self):
        class FakeRedisClient:
            def __init__(self):
                self.storage = {}

            def get(self, key):
                return self.storage.get(key)

            def setex(self, key, ttl, value):
                self.storage[key] = value

            def delete(self, *keys):
                for key in keys:
                    self.storage.pop(key, None)

            def scan(self, cursor, match=None, count=None):
                return 0, []

            def ping(self):
                return True

        cache = RedisGraphCache.__new__(RedisGraphCache)
        cache.client = FakeRedisClient()
        cache.default_ttl = 900
        cache.redis_url = "redis://example.invalid/0"
        return cache

    def test_roundtrip_uses_json_not_pickle(self, cache):
        payload = {
            "alpha": 0.85,
            "cliques": [frozenset({"A", "B"}), frozenset({"C", "D"})],
            "meta": {"count": 2, "enabled": True},
        }

        cache.set("graph:test", payload, ttl=60)

        stored = cache.client.storage["graph:test"]
        assert stored.startswith(b"{")
        assert b"__cache_format__" in stored
        assert cache.get("graph:test") == payload

    def test_rejects_malformed_payload(self, cache):
        cache.client.storage["graph:bad"] = b'{"__cache_format__":1,"value":{"__type__":"evil"}}'

        assert cache.get("graph:bad") is None


class TestCachePerformance:
    """Performance-related cache tests"""

    def test_cache_improves_latency(self):
        """Verify that cache reduces computation time"""
        import time
        
        G = nx.complete_graph(20, create_using=nx.DiGraph)
        for u, v in G.edges():
            G[u][v]["weight"] = 100
        
        cache = GraphOperationCache(backend=InMemoryGraphCache())
        
        # First computation (cache miss)
        start1 = time.perf_counter()
        result1 = cache.cache_betweenness_centrality(G, weight="weight")
        time1 = time.perf_counter() - start1
        
        # Second computation (cache hit)
        start2 = time.perf_counter()
        result2 = cache.cache_betweenness_centrality(G, weight="weight")
        time2 = time.perf_counter() - start2
        
        # Cache hit should be much faster
        assert time2 < time1  # Should be significantly faster
        assert result1 == result2

    def test_cache_hit_rate_for_stable_graphs(self):
        """Test cache effectiveness for stable graphs"""
        G = nx.DiGraph()
        G.add_weighted_edges_from([
            ("A", "B", 100),
            ("B", "C", 100),
            ("C", "A", 100),
        ])
        
        cache = GraphOperationCache(backend=InMemoryGraphCache())
        
        # Multiple calls with same graph
        for _ in range(10):
            cache.cache_pagerank(G, weight="weight")
        
        stats = cache.get_stats()
        assert stats["hit_rate_percent"] == 90.0  # 9 hits out of 10 calls


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
