"""Unit test suite for verifying the Neo4jGraphProvider connection and subgraph extraction operations."""

import os
import unittest
from unittest.mock import MagicMock, patch
import networkx as nx
import time

from src.core.providers.neo4j import Neo4jGraphProvider, NEO4J_AVAILABLE


class TestNeo4jGraphProvider(unittest.TestCase):
    """Test suite validating Neo4j Graph Provider capabilities and mock connections."""

    def setUp(self) -> None:
        self.mock_uri = "bolt://localhost:7687"
        self.mock_user = "neo4j"
        self.mock_password = "password"
        self.env_patcher = patch.dict(
            "os.environ",
            {"AEGIS_NEO4J_URI": self.mock_uri,
             "AEGIS_NEO4J_USER": self.mock_user,
             "AEGIS_NEO4J_PASSWORD": self.mock_password},
        )
        self.env_patcher.start()

    def tearDown(self) -> None:
        self.env_patcher.stop()

    @patch("src.core.providers.neo4j.neo4j", create=True)
    def test_provider_initialization_success(self, mock_neo4j_lib) -> None:
        """Verify driver connectivity check and configuration when Neo4j is available."""
        mock_driver = MagicMock()
        mock_neo4j_lib.GraphDatabase.driver.return_value = mock_driver

        with patch("src.core.providers.neo4j.NEO4J_AVAILABLE", True):
            provider = Neo4jGraphProvider(
                uri=self.mock_uri,
                user=self.mock_user,
                password=self.mock_password,
                enabled=True,
            )

            self.assertTrue(provider.enabled)
            self.assertTrue(provider.is_active)
            mock_neo4j_lib.GraphDatabase.driver.assert_called_once_with(
                "bolt+ssc://localhost:7687",
                auth=(self.mock_user, self.mock_password),
                max_connection_lifetime=3600,
                keep_alive=True,
            )
            mock_driver.verify_connectivity.assert_called_once()

    @patch("src.core.providers.neo4j.neo4j", create=True)
    def test_provider_connectivity_failure_fallback(self, mock_neo4j_lib) -> None:
        """Verify that provider falls back gracefully if connection verification raises an error."""
        mock_driver = MagicMock()
        mock_driver.verify_connectivity.side_effect = Exception("Connection Refused")
        mock_neo4j_lib.GraphDatabase.driver.return_value = mock_driver

        with patch("src.core.providers.neo4j.NEO4J_AVAILABLE", True):
            provider = Neo4jGraphProvider(
                uri=self.mock_uri,
                user=self.mock_user,
                password=self.mock_password,
                enabled=True,
            )

            self.assertFalse(provider.enabled)
            self.assertFalse(provider.is_active)
            self.assertIsNone(provider._driver)

    def test_provider_disabled_by_config(self) -> None:
        """Verify provider operation is completely skipped if disabled by configuration."""
        provider = Neo4jGraphProvider(enabled=False)
        self.assertFalse(provider.enabled)
        self.assertFalse(provider.is_active)

    @patch.dict("os.environ", {}, clear=True)
    def test_provider_handles_missing_credentials_gracefully(self) -> None:
        """Verify that enabling the provider without credentials raises a clear error."""
        with patch("src.core.providers.neo4j.NEO4J_AVAILABLE", False):
            provider = Neo4jGraphProvider(enabled=True)
        
        self.assertFalse(provider.is_active)
        self.assertFalse(provider.enabled)

    def test_provider_resolves_env_vars(self) -> None:
        """Verify that credentials are resolved from environment variables."""
        with patch.dict("os.environ", {
            "NEO4J_URI": "bolt://env-test:7687",
            "NEO4J_USER": "env_user",
            "NEO4J_PASSWORD": "env_pass",
        }, clear=True):
            with patch("src.core.providers.neo4j.NEO4J_AVAILABLE", False):
                provider = Neo4jGraphProvider(enabled=True)
                self.assertEqual(provider.uri, "bolt://env-test:7687")
                self.assertEqual(provider.user, "env_user")
                self.assertEqual(provider.password, "env_pass")

    @patch("src.core.providers.neo4j.neo4j", create=True)
    def test_nodes_edges_count_queries(self, mock_neo4j_lib) -> None:
        """Verify count Cypher queries run session operations and return correct integers."""
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_result_nodes = MagicMock()
        mock_result_edges = MagicMock()

        mock_neo4j_lib.GraphDatabase.driver.return_value = mock_driver
        mock_driver.session.return_value.__enter__.return_value = mock_session

        # Setup node query return
        mock_record_nodes = {"count": 42}
        mock_result_nodes.single.return_value = mock_record_nodes
        
        # Setup edge query return
        mock_record_edges = {"count": 99}
        mock_result_edges.single.return_value = mock_record_edges

        # Mock session.run to return node results first, then edge results
        mock_session.run.side_effect = [mock_result_nodes, mock_result_edges]

        with patch("src.core.providers.neo4j.NEO4J_AVAILABLE", True):
            provider = Neo4jGraphProvider(enabled=True)
            
            # Nodes count
            n_count = provider.number_of_nodes
            self.assertEqual(n_count, 42)
            mock_session.run.assert_any_call("MATCH (n:Account) RETURN count(n) AS count")

            # Edges count
            e_count = provider.number_of_edges
            self.assertEqual(e_count, 99)
            mock_session.run.assert_any_call("MATCH ()-[r:TRANSFER]->() RETURN count(r) AS count")

    @patch("src.core.providers.neo4j.neo4j", create=True)
    def test_add_transaction_execution(self, mock_neo4j_lib) -> None:
        """Verify add_transaction calls Cypher session correctly and invalidates subgraph cache."""
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_neo4j_lib.GraphDatabase.driver.return_value = mock_driver
        mock_driver.session.return_value.__enter__.return_value = mock_session

        with patch("src.core.providers.neo4j.NEO4J_AVAILABLE", True):
            provider = Neo4jGraphProvider(enabled=True)
            
            # Seed cache
            provider._subgraph_cache[provider._cache_key("ACC1", 2)] = (time.time(), nx.DiGraph())
            
            provider.add_transaction("ACC1", "ACC2", 500.0, 12345.6)
            
            # Cache for involved nodes must be cleared
            self.assertNotIn(provider._cache_key("ACC1", 2), provider._subgraph_cache)

            # Query verification
            mock_session.run.assert_called_once()
            args, kwargs = mock_session.run.call_args
            self.assertIn("MERGE (s:Account {id: $src})", args[0])
            self.assertEqual(kwargs["src"], "ACC1")
            self.assertEqual(kwargs["dst"], "ACC2")
            self.assertEqual(kwargs["amount"], 500.0)
            self.assertEqual(kwargs["timestamp"], 12345.6)

    @patch("src.core.providers.neo4j.neo4j", create=True)
    def test_subgraph_extraction_and_mapping(self, mock_neo4j_lib) -> None:
        """Verify k-hop path query is executed and parsed correctly into a NetworkX DiGraph."""
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_result = MagicMock()

        mock_neo4j_lib.GraphDatabase.driver.return_value = mock_driver
        mock_driver.session.return_value.__enter__.return_value = mock_session
        mock_session.run.return_value = mock_result

        # Create mock relationship object
        mock_relationship = MagicMock()
        mock_node_start = MagicMock()
        mock_node_start.get.return_value = "ACC1"
        mock_node_start.__getitem__.return_value = "ACC1"
        
        mock_node_end = MagicMock()
        mock_node_end.get.return_value = "ACC2"
        mock_node_end.__getitem__.return_value = "ACC2"

        mock_relationship.nodes = (mock_node_start, mock_node_end)
        mock_relationship.get.side_effect = lambda key, default=None: {
            "amount": 25000.0,
            "timestamp": 98765.4
        }.get(key, default)

        # Create path mockup record
        mock_path = MagicMock()
        mock_path.relationships = [mock_relationship]
        
        mock_record = {"path": mock_path}
        mock_result.__iter__.return_value = [mock_record]

        with patch("src.core.providers.neo4j.NEO4J_AVAILABLE", True):
            provider = Neo4jGraphProvider(enabled=True, cache_ttl_seconds=10)
            
            # Fetch subgraph
            subgraph = provider.get_approx_subgraph("ACC1", max_hops=2)

            self.assertIsInstance(subgraph, nx.DiGraph)
            self.assertTrue(subgraph.has_node("ACC1"))
            self.assertTrue(subgraph.has_node("ACC2"))
            self.assertTrue(subgraph.has_edge("ACC1", "ACC2"))
            self.assertEqual(subgraph["ACC1"]["ACC2"]["weight"], 25000.0)
            self.assertEqual(subgraph["ACC1"]["ACC2"]["timestamp"], 98765.4)

            # Test TTL caching: a secondary query immediately after should hit in-memory cache and not invoke driver session
            mock_session.reset_mock()
            cached_subgraph = provider.get_approx_subgraph("ACC1", max_hops=2)
            
            self.assertIs(cached_subgraph, subgraph)
            mock_session.run.assert_not_called()

    @patch("src.core.providers.neo4j.neo4j", create=True)
    def test_subgraph_cache_evicts_lru_entry(self, mock_neo4j_lib) -> None:
        """Verify the cache stays bounded and evicts the least-recently-used entry."""
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_neo4j_lib.GraphDatabase.driver.return_value = mock_driver
        mock_driver.session.return_value.__enter__.return_value = mock_session

        def build_result(src_id: str, dst_id: str) -> MagicMock:
            mock_relationship = MagicMock()
            mock_node_start = MagicMock()
            mock_node_start.get.return_value = src_id
            mock_node_start.__getitem__.return_value = src_id

            mock_node_end = MagicMock()
            mock_node_end.get.return_value = dst_id
            mock_node_end.__getitem__.return_value = dst_id

            mock_relationship.nodes = (mock_node_start, mock_node_end)
            mock_relationship.get.side_effect = lambda key, default=None: {
                "amount": 1.0,
                "timestamp": 1.0,
            }.get(key, default)

            mock_path = MagicMock()
            mock_path.relationships = [mock_relationship]

            result = MagicMock()
            result.__iter__.return_value = [{"path": mock_path}]
            return result

        mock_session.run.side_effect = [
            build_result("ACC1", "ACC2"),
            build_result("ACC3", "ACC4"),
        ]

        with patch("src.core.providers.neo4j.NEO4J_AVAILABLE", True):
            provider = Neo4jGraphProvider(enabled=True, cache_ttl_seconds=60, cache_max_entries=1)

            provider.get_approx_subgraph("ACC1", max_hops=2)
            provider.get_approx_subgraph("ACC3", max_hops=2)

            self.assertEqual(list(provider._subgraph_cache.keys()), [provider._cache_key("ACC3", 2)])
            self.assertNotIn(provider._cache_key("ACC1", 2), provider._subgraph_cache)
            self.assertEqual(mock_session.run.call_count, 2)
