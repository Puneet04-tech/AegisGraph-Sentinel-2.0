"""Neo4j graph database provider implementing GraphService boundary."""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from typing import List, Optional, Tuple

import networkx as nx

logger = logging.getLogger(__name__)

# Optional Neo4j Driver Import
try:
    import neo4j
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False


class Neo4jGraphProvider:
    """
    Production-grade Neo4j implementation of the GraphService interface.
    
    Provides thread-safe pool-based connections, Cypher transaction queries,
    and highly performant local subgraph extraction parsed directly into NetworkX.
    """

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "password",
        enabled: bool = True,
        cache_ttl_seconds: int = 60,
        cache_max_entries: int = 1024,
    ) -> None:
        self.uri = uri
        self.user = user
        self.password = password
        self.enabled = enabled and NEO4J_AVAILABLE
        self.cache_ttl_seconds = cache_ttl_seconds
        self.cache_max_entries = cache_max_entries
        if self.cache_max_entries < 1:
            raise ValueError("cache_max_entries must be at least 1")

        self._driver: Optional[neo4j.Driver] = None
        self._subgraph_cache: OrderedDict[str, Tuple[float, nx.DiGraph]] = OrderedDict()

        if not NEO4J_AVAILABLE and enabled:
            logger.warning(
                "Neo4j client library is not installed. Falling back to offline mode. "
                "Run `pip install neo4j` to enable active database integrations."
            )
            self.enabled = False

        if self.enabled:
            try:
                self._driver = neo4j.GraphDatabase.driver(
                    self.uri,
                    auth=(self.user, self.password),
                    max_connection_lifetime=3600,
                    keep_alive=True,
                )
                # Verify connectivity immediately
                self._driver.verify_connectivity()
                logger.info(f"✓ Successfully connected to Neo4j database at {self.uri}")
            except Exception as e:
                logger.error(
                    f"⚠ Failed to establish a connection pool to Neo4j: {e}. "
                    "Operating in offline graceful fallback mode."
                )
                self.enabled = False
                self._driver = None

    def _get_cached_subgraph(self, account_id: str, now: float) -> Optional[nx.DiGraph]:
        cached_entry = self._subgraph_cache.get(account_id)
        if not cached_entry:
            return None

        cache_time, cached_graph = cached_entry
        if now - cache_time >= self.cache_ttl_seconds:
            self._subgraph_cache.pop(account_id, None)
            return None

        self._subgraph_cache.move_to_end(account_id)
        return cached_graph

    def _store_cached_subgraph(self, account_id: str, graph: nx.DiGraph, now: float) -> None:
        self._subgraph_cache[account_id] = (now, graph)
        self._subgraph_cache.move_to_end(account_id)

        while len(self._subgraph_cache) > self.cache_max_entries:
            self._subgraph_cache.popitem(last=False)

    @property
    def is_active(self) -> bool:
        """Check if the Neo4j provider is successfully running and active."""
        return self.enabled and self._driver is not None

    @property
    def number_of_nodes(self) -> int:
        if not self.is_active:
            return 0
        query = "MATCH (n:Account) RETURN count(n) AS count"
        try:
            with self._driver.session() as session:
                result = session.run(query)
                record = result.single()
                return record["count"] if record else 0
        except Exception as e:
            logger.error(f"Error querying node count from Neo4j: {e}")
            return 0

    @property
    def number_of_edges(self) -> int:
        if not self.is_active:
            return 0
        query = "MATCH ()-[r:TRANSFER]->() RETURN count(r) AS count"
        try:
            with self._driver.session() as session:
                result = session.run(query)
                record = result.single()
                return record["count"] if record else 0
        except Exception as e:
            logger.error(f"Error querying edge count from Neo4j: {e}")
            return 0

    def nodes(self) -> List[str]:
        if not self.is_active:
            return []
        query = "MATCH (n:Account) RETURN n.id AS id"
        try:
            with self._driver.session() as session:
                result = session.run(query)
                return [record["id"] for record in result if record.get("id")]
        except Exception as e:
            logger.error(f"Error querying node list from Neo4j: {e}")
            return []

    def edges(self) -> List[Tuple[str, str]]:
        if not self.is_active:
            return []
        query = "MATCH (s:Account)-[:TRANSFER]->(d:Account) RETURN s.id AS src, d.id AS dst"
        try:
            with self._driver.session() as session:
                result = session.run(query)
                return [(record["src"], record["dst"]) for record in result if record.get("src") and record.get("dst")]
        except Exception as e:
            logger.error(f"Error querying edge list from Neo4j: {e}")
            return []

    def add_transaction(
        self,
        src_account: str,
        dst_account: str,
        amount: float,
        timestamp: float,
    ) -> None:
        """Create or update nodes and write an active transaction relationship to Neo4j."""
        if not self.is_active:
            return

        query = (
            "MERGE (s:Account {id: $src})\n"
            "MERGE (d:Account {id: $dst})\n"
            "CREATE (s)-[r:TRANSFER {amount: $amount, timestamp: $timestamp}]->(d)"
        )
        try:
            with self._driver.session() as session:
                session.run(
                    query,
                    src=src_account,
                    dst=dst_account,
                    amount=amount,
                    timestamp=timestamp,
                )
            # Invalidate any cached local subgraphs for the involved accounts
            self._subgraph_cache.pop(src_account, None)
            self._subgraph_cache.pop(dst_account, None)
        except Exception as e:
            logger.error(f"Failed to record transaction {src_account} -> {dst_account} in Neo4j: {e}")

    DEFAULT_SUBGRAPH_LIMIT = 10_000

    def get_approx_subgraph(self, account_id: str, max_hops: int = 2) -> nx.DiGraph:
        """
        Extract the k-hop local transaction network around an account ID from Neo4j,
        reconstructing it as a directed NetworkX DiGraph.
        """
        if not self.is_active:
            # Return an empty graph if the provider is offline
            G = nx.DiGraph()
            G.add_node(account_id)
            return G

        # Check in-memory TTL cache
        now = time.time()
        cached_graph = self._get_cached_subgraph(account_id, now)
        if cached_graph is not None:
            return cached_graph

        G = nx.DiGraph()
        G.add_node(account_id)

        # Retrieve paths matching the k-hop undirected pattern with a hard limit
        # to prevent super-node DoS (issue #477).
        limit = self.DEFAULT_SUBGRAPH_LIMIT
        query = (
            "MATCH path = (a:Account {id: $account_id})-[r:TRANSFER*1..2]-(b:Account)\n"
            "RETURN path\n"
            "LIMIT $limit"
        )
        try:
            with self._driver.session() as session:
                result = session.run(query, account_id=account_id, limit=limit)
                for record in result:
                    path = record["path"]
                    for relationship in path.relationships:
                        start_node = relationship.nodes[0]
                        end_node = relationship.nodes[1]
                        
                        start_id = start_node["id"]
                        end_id = end_node["id"]

                        amount = relationship.get("amount", 0.0)
                        timestamp = relationship.get("timestamp", 0.0)

                        G.add_edge(start_id, end_id, weight=amount, timestamp=timestamp)
            self._store_cached_subgraph(account_id, G, now)
            return G
        except Exception as e:
            logger.error(f"Error extracting subgraph for account {account_id}: {e}")
            return G

    def close(self) -> None:
        """Release connection pool handles."""
        if self._driver:
            try:
                self._driver.close()
                logger.info("Neo4j connection pool cleanly closed.")
            except Exception as e:
                logger.error(f"Error closing Neo4j driver: {e}")
            finally:
                self._driver = None
                self.enabled = False
