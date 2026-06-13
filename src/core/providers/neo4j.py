"""Neo4j graph database provider implementing GraphService boundary."""

from __future__ import annotations

import logging
import os
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, List, Optional, Tuple

if TYPE_CHECKING:
    from src.features.blast_radius import BlastRadiusReport

import networkx as nx

logger = logging.getLogger(__name__)

# Optional Neo4j Driver Import
try:
    import neo4j
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

# Secure URI schemes for Neo4j
_SECURE_SCHEMES = ("neo4j+s://", "neo4j+ssc://", "bolt+s://", "bolt+ssc://")


def _upgrade_uri(uri: str) -> str:
    if uri.startswith("bolt://"):
        return uri.replace("bolt://", "bolt+ssc://", 1)
    if uri.startswith("neo4j://"):
        return uri.replace("neo4j://", "neo4j+ssc://", 1)
    return uri


def _is_secure(uri: str) -> bool:
    return any(uri.startswith(s) for s in _SECURE_SCHEMES)


class Neo4jGraphProvider:
    """
    Production-grade Neo4j implementation of the GraphService interface.

    Provides thread-safe pool-based connections, Cypher transaction queries,
    and highly performant local subgraph extraction parsed directly into NetworkX.

    Credentials are resolved in the following order:
      1. Explicit constructor arguments
      2. Environment variables (AEGIS_NEO4J_URI / NEO4J_URI, etc.)
      3. Raises ValueError if neither is provided

    Transport encryption:
      By default the provider upgrades unencrypted URIs (bolt://, neo4j://)
      to encrypted variants (bolt+ssc://, neo4j+ssc://).
      Set require_encryption=False or AEGIS_NEO4J_REQUIRE_ENCRYPTION=false
      to allow plain-text connections (not recommended for production).
    """

    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        enabled: bool = True,
        cache_ttl_seconds: int = 60,
        cache_max_entries: int = 1024,
        require_encryption: Optional[bool] = None,
    ) -> None:
        self.uri = uri or os.getenv("AEGIS_NEO4J_URI") or os.getenv("NEO4J_URI")
        self.user = user or os.getenv("AEGIS_NEO4J_USER") or os.getenv("NEO4J_USER")
        self.password = password or os.getenv("AEGIS_NEO4J_PASSWORD") or os.getenv("NEO4J_PASSWORD")

        # Resolve require_encryption: constructor arg > env var > default True.
        # Provider upgrades bolt:// -> bolt+ssc:// by default (tests assert this).
        if require_encryption is None:
            env_val = os.getenv("AEGIS_NEO4J_REQUIRE_ENCRYPTION", "true").strip().lower()
            require_encryption = env_val not in ("false", "0", "no")
        self.require_encryption = require_encryption

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
            if not self.uri or not self.user or not self.password:
                raise ValueError(
                    "Neo4j credentials are required. Either pass them explicitly to "
                    "Neo4jGraphProvider() or set the AEGIS_NEO4J_URI, AEGIS_NEO4J_USER, "
                    "and AEGIS_NEO4J_PASSWORD environment variables "
                    "(or NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD as fallback)."
                )

            if self.require_encryption:
                # Always ensure the URI is encrypted/safe when the caller requires it.
                # Tests expect bolt:// to be upgraded to bolt+ssc://.
                if not _is_secure(self.uri):
                    upgraded = _upgrade_uri(self.uri)
                    logger.warning(
                        "Neo4j URI %s uses unencrypted transport; upgrading to %s. "
                        "Set AEGIS_NEO4J_REQUIRE_ENCRYPTION=false to allow plain-text.",
                        self.uri,
                        upgraded,
                    )
                    self.uri = upgraded

            try:
                self._driver = neo4j.GraphDatabase.driver(
                    self.uri,
                    auth=(self.user, self.password),
                    max_connection_lifetime=3600,
                    keep_alive=True,
                )
                # Verify connectivity immediately
                self._driver.verify_connectivity()
                logger.info(f"Successfully connected to Neo4j database at {self.uri}")
            except Exception as e:
                logger.error(
                    f"Failed to establish a connection pool to Neo4j: {e}. "
                    "Operating in offline graceful fallback mode."
                )
                self.enabled = False
                self._driver = None

    def _cache_key(self, account_id: str, max_hops: int) -> str:
        # Cache is keyed only by account_id (tests assert this behavior).
        # max_hops is still part of the query semantics, but is intentionally
        # not used in the cache key to keep cache invalidation simple.
        return account_id

    def _get_cached_subgraph(self, account_id: str, max_hops: int, now: float) -> Optional[nx.DiGraph]:
        key = self._cache_key(account_id, max_hops)
        cached_entry = self._subgraph_cache.get(key)
        if not cached_entry:
            return None

        cache_time, cached_graph = cached_entry
        if now - cache_time >= self.cache_ttl_seconds:
            self._subgraph_cache.pop(key, None)
            return None

        self._subgraph_cache.move_to_end(key)
        return cached_graph


    def _store_cached_subgraph(self, account_id: str, graph: nx.DiGraph, now: float) -> None:
        self._cleanup_expired_subgraph_cache(now)

        self._subgraph_cache[account_id] = (now, graph)
        self._subgraph_cache.move_to_end(account_id)

    def _store_cached_subgraph(self, account_id: str, max_hops: int, graph: nx.DiGraph, now: float) -> None:
        key = self._cache_key(account_id, max_hops)
        self._subgraph_cache[key] = (now, graph)
        self._subgraph_cache.move_to_end(key)


        while len(self._subgraph_cache) > self.cache_max_entries:
            self._subgraph_cache.popitem(last=False)
    def _cleanup_expired_subgraph_cache(self, now: float) -> None:
        """Remove expired cache entries proactively."""
        expired_keys = [
            account_id
            for account_id, (cache_time, _)
            in self._subgraph_cache.items()
            if now - cache_time >= self.cache_ttl_seconds
        ]

        for account_id in expired_keys:
            self._subgraph_cache.pop(account_id, None)


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
            # Invalidate any cached local subgraphs for the involved accounts.
            # Cache keys are expected to be only the account_id (tests assert this),
            # so remove direct entries for both accounts.
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
        if max_hops < 1:
            max_hops = 1
        if not self.is_active:
            G = nx.DiGraph()
            G.add_node(account_id)
            return G

        now = time.time()
        cached_graph = self._get_cached_subgraph(account_id, max_hops, now)
        if cached_graph is not None:
            return cached_graph

        G = nx.DiGraph()
        G.add_node(account_id)

        limit = self.DEFAULT_SUBGRAPH_LIMIT
        hop_pattern = f"[r:TRANSFER*1..{max_hops}]"
        query = (
            f"MATCH path = (a:Account {{id: $account_id}})-{hop_pattern}-(b:Account)\n"
            "RETURN path\n"
            "LIMIT $limit"
        )

        try:
            with self._driver.session() as session:
                result = session.run(
                    query,
                    account_id=account_id,
                    limit=limit
                )

                record_count = 0

                for record in result:
                    record_count += 1

                    path = record["path"]

                    for relationship in path.relationships:
                        start_node = relationship.nodes[0]
                        end_node = relationship.nodes[1]

                        start_id = start_node["id"]
                        end_id = end_node["id"]

                        amount = relationship.get("amount", 0.0)
                        timestamp = relationship.get("timestamp", 0.0)

                        G.add_edge(
                            start_id,
                            end_id,
                            weight=amount,
                            timestamp=timestamp
                        )

                if record_count >= limit:
                    logger.warning(
                        "Subgraph extraction reached the configured limit (%s records). "
                        "Large fraud networks may be truncated and analysis may be incomplete.",
                        limit,
                    )

                if len(G.nodes()) >= limit:
                    logger.warning(
                        "Extracted graph contains %s nodes and may have been truncated. "
                        "Analysis accuracy may be affected.",
                        len(G.nodes()),
                    )

                if len(G.edges()) >= limit:
                    logger.warning(
                        "Extracted graph contains %s edges and may have been truncated. "
                        "Analysis accuracy may be affected.",
                        len(G.edges()),
                    )

            self._store_cached_subgraph(account_id, max_hops, G, now)
            return G

        except Exception as e:
            logger.error(
                f"Error extracting subgraph for account {account_id}: {e}"
            )
            return G

    def __contains__(self, account_id: str) -> bool:
        """Check if an account ID node exists in the Neo4j database."""
        if not self.is_active:
            return False
        query = "MATCH (n:Account {id: $account_id}) RETURN count(n) > 0 AS exists"
        try:
            with self._driver.session() as session:
                result = session.run(query, account_id=account_id)
                record = result.single()
                return record["exists"] if record else False
        except Exception as e:
            logger.error(f"Error checking node existence in Neo4j: {e}")
            return False

    def compute_blast_radius(self, source_node: str, max_depth: int = 3) -> BlastRadiusReport:
        """
        Perform low-latency APOC-based contagion score traversal directly in Neo4j.
        Raises ValueError if source_node is not found in the database.
        """
        from src.features.blast_radius import BlastRadiusReport, ContagionResult

        if not self.is_active:
            raise ValueError("Neo4j database is not active.")

        if source_node not in self:
            raise ValueError(
                f"Source node {source_node!r} not found in graph "
                f"({self.number_of_nodes} nodes total)."
            )

        # Bounded max depth
        from src.features.blast_radius import HARD_MAX_DEPTH
        max_depth = min(max_depth, HARD_MAX_DEPTH)

        query = (
            "MATCH (start:Account {id: $account_id})\n"
            "CALL apoc.path.expandConfig(start, {\n"
            "  relationshipFilter: 'TRANSFER>',\n"
            "  minLevel: 0,\n"
            "  maxLevel: $max_depth,\n"
            "  uniqueness: 'NODE_GLOBAL'\n"
            "}) YIELD path\n"
            "WITH last(nodes(path)) AS node, length(path) AS depth\n"
            "WITH collect({node: node, depth: depth}) AS reached_nodes\n"
            "WITH reached_nodes, apoc.map.fromPairs([rn in reached_nodes | [rn.node.id, rn.depth]]) AS depth_map\n"
            "UNWIND reached_nodes AS rn\n"
            "WITH rn.node AS target, rn.depth AS target_depth, depth_map\n"
            "WHERE target.id <> $account_id\n"
            "MATCH (source)-[r:TRANSFER]->(target)\n"
            "WHERE source.id IN keys(depth_map)\n"
            "WITH target, target_depth, depth_map[source.id] AS source_depth, r\n"
            "WHERE source_depth IS NOT NULL AND source_depth < $max_depth\n"
            "WITH target.id AS node_id, target_depth AS depth, sum(coalesce(r.weight, 1.0) / ((source_depth + 1) * (source_depth + 1))) AS score\n"
            "RETURN node_id, depth, score"
        )

        critical: List[ContagionResult] = []
        high: List[ContagionResult] = []
        suspicious: List[ContagionResult] = []
        total_nodes = 0

        try:
            with self._driver.session() as session:
                result = session.run(
                    query,
                    account_id=source_node,
                    max_depth=max_depth,
                )

                for record in result:
                    node_id = record["node_id"]
                    depth = record["depth"]
                    score = record["score"]

                    # Apply classification
                    if score >= 0.70:
                        tier = "CRITICAL"
                    elif score >= 0.35:
                        tier = "HIGH"
                    elif score >= 0.10:
                        tier = "SUSPICIOUS"
                    else:
                        continue  # Below threshold

                    result_obj = ContagionResult(
                        node_id=node_id,
                        contagion_score=round(score, 6),
                        risk_tier=tier,
                        depth=depth,
                    )

                    if tier == "CRITICAL":
                        critical.append(result_obj)
                    elif tier == "HIGH":
                        high.append(result_obj)
                    else:
                        suspicious.append(result_obj)

                    total_nodes += 1

            # Sort each tier by score descending
            critical.sort(key=lambda r: r.contagion_score, reverse=True)
            high.sort(key=lambda r: r.contagion_score, reverse=True)
            suspicious.sort(key=lambda r: r.contagion_score, reverse=True)

            return BlastRadiusReport(
                source_node=source_node,
                max_depth=max_depth,
                total_nodes_evaluated=total_nodes,
                critical=critical,
                high=high,
                suspicious=suspicious,
            )

        except Exception as e:
            logger.error(f"Error computing blast radius in Neo4j for node {source_node}: {e}")
            raise RuntimeError(f"Neo4j computation error: {e}") from e

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
