"""
Graph Operation Caching Layer

Implements intelligent caching for expensive NetworkX graph operations
(betweenness centrality, PageRank, clique detection) to reduce latency.

Supports both Redis (production) and in-memory (testing) backends.
"""

import hashlib
import json
import logging
import os
import threading
import time
from abc import ABC, abstractmethod
from functools import wraps
from collections import OrderedDict
from typing import Any, Callable, Dict, Optional, Set, Tuple

import networkx as nx

logger = logging.getLogger(__name__)

# Optional Redis import for production
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class GraphCache(ABC):
    """Abstract base class for graph operation caching."""

    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Retrieve value from cache."""
        pass

    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Store value in cache with optional TTL (seconds)."""
        pass

    @abstractmethod
    def invalidate(self, key: str) -> None:
        """Remove specific key from cache."""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear entire cache."""
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics (hits, misses, size)."""
        pass


class InMemoryGraphCache(GraphCache):
    """Thread-safe in-memory cache for testing and single-worker deployment."""

    def __init__(self, max_size: int = 1000):
        """
        Initialize in-memory cache.
        
        Args:
            max_size: Maximum number of cache entries
        """
        self.cache: "OrderedDict[str, Tuple[Any, Optional[int], float]]" = OrderedDict()
        self.max_size = max_size
        self.hits = 0
        self.misses = 0
        self._lock = threading.RLock()

    def _purge_expired_locked(self, now: Optional[float] = None) -> None:
        """Remove expired entries before reads or capacity-based eviction."""
        if now is None:
            now = time.time()

        expired_keys = [
            key
            for key, (_, ttl, stored_at) in self.cache.items()
            if ttl is not None and now - stored_at >= ttl
        ]
        for key in expired_keys:
            del self.cache[key]
            logger.debug(f"Cache expired: {key}")

    def _evict_if_needed_locked(self) -> None:
        """Evict least-recently-used entries while the cache exceeds capacity."""
        while len(self.cache) > self.max_size:
            oldest_key, _ = self.cache.popitem(last=False)
            logger.debug(f"Cache evicted: {oldest_key}")

    def get(self, key: str) -> Optional[Any]:
        """Retrieve value, returns None if not found."""
        with self._lock:
            now = time.time()
            self._purge_expired_locked(now)

            if key in self.cache:
                value, _, _ = self.cache[key]
                self.cache.move_to_end(key)
                self.hits += 1
                logger.debug(f"Cache HIT: {key}")
                return value

            self.misses += 1
            logger.debug(f"Cache MISS: {key}")
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Store value with optional TTL."""
        with self._lock:
            now = time.time()
            self._purge_expired_locked(now)
            self.cache[key] = (value, ttl, now)
            self.cache.move_to_end(key)
            self._evict_if_needed_locked()
            logger.debug(f"Cache SET: {key} (ttl={ttl}s)")

    def invalidate(self, key: str) -> None:
        """Remove specific key from cache."""
        with self._lock:
            if key in self.cache:
                del self.cache[key]
                logger.debug(f"Cache INVALIDATE: {key}")

    def clear(self) -> None:
        """Clear entire cache."""
        with self._lock:
            self.cache.clear()
            logger.info("Cache cleared")

    def get_stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        with self._lock:
            self._purge_expired_locked()
            total = self.hits + self.misses
            hit_rate = (self.hits / total * 100) if total > 0 else 0.0

            return {
                "backend": "in_memory",
                "size": len(self.cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "total_requests": total,
                "hit_rate_percent": round(hit_rate, 2),
            }


class RedisGraphCache(GraphCache):
    """Redis-backed cache for production multi-worker deployment."""

    _FORMAT_VERSION = 1

    def __init__(self, redis_url: str, default_ttl: int = 900):
        """
        Initialize Redis cache.
        
        Args:
            redis_url: Redis connection string (e.g., 'redis://localhost:6379/0')
            default_ttl: Default TTL in seconds (900 = 15 minutes)
        """
        self.redis_url = redis_url
        self.default_ttl = default_ttl
        try:
            self.client = redis.from_url(redis_url, decode_responses=False)
            self.client.ping()
            logger.info("Connected to Redis cache backend")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    def get(self, key: str) -> Optional[Any]:
        """Retrieve and deserialize value from Redis."""
        try:
            data = self.client.get(key)
            if data:
                logger.debug(f"Cache HIT: {key}")
                return self._deserialize_value(data)
            logger.debug(f"Cache MISS: {key}")
            return None
        except Exception as e:
            logger.error(f"Cache GET error: {e}")
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Serialize and store value in Redis."""
        try:
            ttl = ttl or self.default_ttl
            serialized = self._serialize_value(value)
            self.client.setex(key, ttl, serialized)
            logger.debug(f"Cache SET: {key} (ttl={ttl}s)")
        except Exception as e:
            logger.error(f"Cache SET error: {e}")

    def _serialize_value(self, value: Any) -> bytes:
        """Serialize cache payloads to a JSON document."""
        def encode(obj: Any) -> Any:
            if isinstance(obj, frozenset):
                return {"__type__": "frozenset", "items": [encode(item) for item in sorted(obj, key=repr)]}
            if isinstance(obj, tuple):
                return {"__type__": "tuple", "items": [encode(item) for item in obj]}
            if isinstance(obj, list):
                return [encode(item) for item in obj]
            if isinstance(obj, dict):
                return {str(key): encode(item) for key, item in obj.items()}
            return obj

        payload = {
            "__cache_format__": self._FORMAT_VERSION,
            "value": encode(value),
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def _deserialize_value(self, payload: bytes) -> Any:
        """Deserialize cache payloads from JSON and reconstruct tagged types."""
        def decode(obj: Any) -> Any:
            if isinstance(obj, dict):
                obj_type = obj.get("__type__")
                if obj_type == "frozenset":
                    return frozenset(decode(item) for item in obj.get("items", []))
                if obj_type == "tuple":
                    return tuple(decode(item) for item in obj.get("items", []))
                if obj_type is not None:
                    raise ValueError(f"Unsupported cached object type: {obj_type}")
                return {key: decode(item) for key, item in obj.items()}
            if isinstance(obj, list):
                return [decode(item) for item in obj]
            return obj

        loaded = json.loads(payload.decode("utf-8"))
        if not isinstance(loaded, dict) or loaded.get("__cache_format__") != self._FORMAT_VERSION:
            raise ValueError("Unsupported cache payload format")
        return decode(loaded["value"])

    def invalidate(self, key: str) -> None:
        """Remove specific key from Redis."""
        try:
            self.client.delete(key)
            logger.debug(f"Cache INVALIDATE: {key}")
        except Exception as e:
            logger.error(f"Cache INVALIDATE error: {e}")

    def clear(self) -> None:
        """Clear all cache keys with 'graph:' prefix."""
        try:
            cursor = 0
            while True:
                cursor, keys = self.client.scan(cursor, match="graph:*", count=100)
                if keys:
                    self.client.delete(*keys)
                if cursor == 0:
                    break
            logger.info("Cache cleared")
        except Exception as e:
            logger.error(f"Cache CLEAR error: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Return Redis cache statistics."""
        try:
            info = self.client.info()
            return {
                "backend": "redis",
                "used_memory_mb": info.get("used_memory", 0) / (1024 * 1024),
                "connected_clients": info.get("connected_clients", 0),
                "total_commands": info.get("total_commands_processed", 0),
            }
        except Exception as e:
            logger.error(f"Cache STATS error: {e}")
            return {"backend": "redis", "error": str(e)}


class GraphOperationCache:
    """
    High-level interface for caching graph operations.
    
    Handles graph hashing, cache key generation, and operation-specific caching.
    """

    def __init__(self, backend: Optional[GraphCache] = None):
        """
        Initialize with cache backend (Redis or in-memory).
        
        Args:
            backend: GraphCache instance. If None, uses in-memory cache.
        """
        if backend is None:
            # Try Redis first, fall back to in-memory
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            if REDIS_AVAILABLE:
                try:
                    backend = RedisGraphCache(redis_url)
                except Exception as e:
                    logger.warning(f"Redis unavailable, using in-memory cache: {e}")
                    backend = InMemoryGraphCache()
            else:
                backend = InMemoryGraphCache()

        self.backend = backend
        logger.info(f"Graph operation cache initialized with {type(backend).__name__}")

    @staticmethod
    def _hash_graph(graph: nx.DiGraph) -> str:
        """
        Generate deterministic hash for graph structure.

        Includes edges, edge payloads, node count, isolated nodes, and
        node degree sums to detect structural changes that edges alone
        would miss (e.g. adding or removing isolated nodes).
        """
        def edge_payload(u, v):
            if hasattr(graph, "get_edge_data"):
                data = graph.get_edge_data(u, v, default={}) or {}
            else:
                data = getattr(graph, "_edge_attrs", {}).get((u, v), {})
            return tuple((key, repr(value)) for key, value in sorted(data.items()))

        edges = sorted(
            (
                u,
                v,
                edge_payload(u, v),
            )
            for u, v in graph.edges()
        )

        isolated_nodes = sorted(
            n for n in graph.nodes() if graph.degree(n) == 0
        )
        node_count = graph.number_of_nodes()
        degree_sig = tuple(
            sorted((n, d) for n, d in graph.degree())
        )

        payload = (
            node_count,
            tuple(isolated_nodes),
            degree_sig,
            edges,
        )
        return hashlib.sha256(repr(payload).encode()).hexdigest()[:16]

    @staticmethod
    def _hash_params(**params) -> str:
        """Generate hash for function parameters."""
        param_str = str(sorted(params.items())).encode()
        return hashlib.sha256(param_str).hexdigest()[:8]

    def cache_betweenness_centrality(
        self,
        graph: nx.DiGraph,
        weight: Optional[str] = None,
        k: Optional[int] = None,
        ttl: int = 900,
    ) -> Dict[str, float]:
        """
        Cache wrapper for nx.betweenness_centrality.
        
        Args:
            graph: Input directed graph
            weight: Edge weight attribute name
            k: Number of nodes to sample (approximate)
            ttl: Cache TTL in seconds
        
        Returns:
            Betweenness centrality dictionary
        """
        graph_hash = self._hash_graph(graph)
        params_hash = self._hash_params(weight=weight, k=k, normalized=True)
        cache_key = f"graph:betweenness:{graph_hash}:{params_hash}"

        # Try cache
        cached = self.backend.get(cache_key)
        if cached is not None:
            return cached

        # Compute
        centrality = nx.betweenness_centrality(
            graph, weight=weight, k=k, normalized=True
        )

        # Store in cache
        self.backend.set(cache_key, centrality, ttl)
        return centrality

    def cache_pagerank(
        self,
        graph: nx.DiGraph,
        alpha: float = 0.85,
        weight: Optional[str] = None,
        max_iter: int = 100,
        ttl: int = 900,
    ) -> Dict[str, float]:
        """
        Cache wrapper for nx.pagerank.
        
        Args:
            graph: Input directed graph
            alpha: Damping factor
            weight: Edge weight attribute name
            max_iter: Maximum iterations
            ttl: Cache TTL in seconds
        
        Returns:
            PageRank score dictionary
        """
        graph_hash = self._hash_graph(graph)
        params_hash = self._hash_params(
            alpha=alpha, weight=weight, max_iter=max_iter
        )
        cache_key = f"graph:pagerank:{graph_hash}:{params_hash}"

        # Try cache
        cached = self.backend.get(cache_key)
        if cached is not None:
            return cached

        # Compute
        pagerank = nx.pagerank(graph, alpha=alpha, weight=weight, max_iter=max_iter)

        # Store in cache
        self.backend.set(cache_key, pagerank, ttl)
        return pagerank

    def cache_find_cliques(
        self,
        graph: nx.Graph,
        ttl: int = 900,
    ) -> list:
        """
        Cache wrapper for nx.find_cliques.
        
        Args:
            graph: Input undirected graph
            ttl: Cache TTL in seconds
        
        Returns:
            List of cliques (each clique is a frozenset of nodes)
        """
        graph_hash = self._hash_graph(graph)  # Works for undirected too
        cache_key = f"graph:cliques:{graph_hash}"

        # Try cache
        cached = self.backend.get(cache_key)
        if cached is not None:
            return cached

        # Compute
        cliques = [frozenset(c) for c in nx.find_cliques(graph)]

        # Store in cache
        self.backend.set(cache_key, cliques, ttl)
        return cliques

    def invalidate_graph(self, graph: nx.DiGraph) -> None:
        """Invalidate all cached operations for a graph."""
        graph_hash = self._hash_graph(graph)

        # Cliques key has no params hash — exact key works
        self.backend.invalidate(f"graph:cliques:{graph_hash}")

        # Betweenness and pagerank include a params hash suffix — use prefix scan
        for operation in ["betweenness", "pagerank"]:
            prefix = f"graph:{operation}:{graph_hash}:"
            self._invalidate_by_prefix(prefix)

        logger.info(f"Invalidated cache for graph {graph_hash}")

    def _invalidate_by_prefix(self, prefix: str) -> None:
        """Delete all cache keys that start with the given prefix."""
        if isinstance(self.backend, RedisGraphCache):
            try:
                cursor = 0
                while True:
                    cursor, keys = self.backend.client.scan(
                        cursor, match=f"{prefix}*", count=100
                    )
                    if keys:
                        self.backend.client.delete(*keys)
                    if cursor == 0:
                        break
            except Exception as e:
                logger.error(f"Prefix invalidation error for {prefix}: {e}")
        elif isinstance(self.backend, InMemoryGraphCache):
            with self.backend._lock:
                keys_to_delete = [
                    k for k in self.backend.cache if k.startswith(prefix)
                ]
                for k in keys_to_delete:
                    del self.backend.cache[k]
                    logger.debug(f"Cache INVALIDATE: {k}")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return self.backend.get_stats()

    def clear(self) -> None:
        """Clear entire cache."""
        self.backend.clear()


# Global cache instance
_cache_instance: Optional[GraphOperationCache] = None
_cache_lock = threading.Lock()


def get_graph_cache() -> GraphOperationCache:
    """Get or create global cache instance (singleton pattern)."""
    global _cache_instance
    with _cache_lock:
        if _cache_instance is None:
            _cache_instance = GraphOperationCache()
        return _cache_instance


def reset_cache() -> None:
    """Reset global cache instance (for testing)."""
    global _cache_instance
    with _cache_lock:
        _cache_instance = None
