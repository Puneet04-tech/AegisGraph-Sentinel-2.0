"""
Tests for Graph Analytics Platform
"""

import pytest
import threading
import time

from src.graph_analytics.models import (
    GraphNode,
    GraphEdge,
    NodeType,
    EdgeType,
)
from src.graph_analytics.store import get_graph_store, reset_graph_store
from src.graph_analytics.service import get_graph_service, reset_graph_service


class TestGraphModels:
    """Tests for graph data models."""

    def test_create_graph_node(self):
        """Test creating a graph node."""
        node = GraphNode(
            node_id="test_node",
            node_type=NodeType.ACCOUNT,
            label="Test Account",
            properties={"account_type": "checking"},
            risk_score=0.7,
        )
        assert node.node_id == "test_node"
        assert node.node_type == NodeType.ACCOUNT
        assert node.risk_score == 0.7

    def test_create_graph_edge(self):
        """Test creating a graph edge."""
        edge = GraphEdge(
            source_id="node1",
            target_id="node2",
            edge_type=EdgeType.SENT_TO,
            weight=1.5,
        )
        assert edge.source_id == "node1"
        assert edge.target_id == "node2"
        assert edge.weight == 1.5


class TestGraphStore:
    """Tests for graph store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_graph_store()

    def test_add_and_get_node(self):
        """Test adding and retrieving a node."""
        store = get_graph_store()
        node = GraphNode(
            node_id="test",
            node_type=NodeType.ENTITY,
            label="Test",
        )
        store.add_node(node)

        retrieved = store.get_node("test")
        assert retrieved is not None
        assert retrieved.label == "Test"

    def test_add_and_get_edge(self):
        """Test adding and retrieving an edge."""
        store = get_graph_store()
        node1 = GraphNode(node_id="n1", node_type=NodeType.ENTITY)
        node2 = GraphNode(node_id="n2", node_type=NodeType.ENTITY)
        store.add_node(node1)
        store.add_node(node2)

        edge = GraphEdge(source_id="n1", target_id="n2", edge_type=EdgeType.LINKED_TO)
        store.add_edge(edge)

        neighbors = store.get_neighbors("n1")
        assert len(neighbors) == 1
        assert neighbors[0].node_id == "n2"

    def test_bfs_traverse(self):
        """Test BFS traversal."""
        store = get_graph_store()
        for i in range(5):
            store.add_node(GraphNode(node_id=f"n{i}", node_type=NodeType.ENTITY))

        store.add_edge(GraphEdge(source_id="n0", target_id="n1"))
        store.add_edge(GraphEdge(source_id="n1", target_id="n2"))
        store.add_edge(GraphEdge(source_id="n0", target_id="n3"))

        result = store.bfs_traverse("n0", max_depth=2)
        assert len(result) == 4

    def test_find_shortest_path(self):
        """Test finding shortest path."""
        store = get_graph_store()
        for i in range(5):
            store.add_node(GraphNode(node_id=f"n{i}", node_type=NodeType.ENTITY))

        store.add_edge(GraphEdge(source_id="n0", target_id="n1"))
        store.add_edge(GraphEdge(source_id="n1", target_id="n2"))
        store.add_edge(GraphEdge(source_id="n2", target_id="n3"))
        store.add_edge(GraphEdge(source_id="n0", target_id="n4"))

        path = store.find_shortest_path("n0", "n3")
        assert path == ["n0", "n1", "n2", "n3"]

    def test_detect_communities(self):
        """Test community detection."""
        store = get_graph_store()
        for i in range(6):
            store.add_node(GraphNode(node_id=f"n{i}", node_type=NodeType.ENTITY))

        for i in range(2):
            store.add_edge(GraphEdge(source_id=f"n{i}", target_id=f"n{i+1}"))
        for i in range(3, 5):
            store.add_edge(GraphEdge(source_id=f"n{i}", target_id=f"n{i+1}"))

        communities = store.detect_communities()
        assert len(communities) >= 1

    def test_propagate_risk(self):
        """Test risk propagation."""
        store = get_graph_store()
        for i in range(4):
            risk = 0.8 if i == 0 else 0.0
            store.add_node(GraphNode(node_id=f"n{i}", node_type=NodeType.ENTITY, risk_score=risk))

        store.add_edge(GraphEdge(source_id="n0", target_id="n1"))
        store.add_edge(GraphEdge(source_id="n1", target_id="n2"))
        store.add_edge(GraphEdge(source_id="n2", target_id="n3"))

        result = store.propagate_risk("n0", max_depth=3)
        assert len(result.affected_nodes) == 4
        assert result.risk_scores["n0"] == 0.8


class TestGraphService:
    """Tests for graph service."""

    def setup_method(self):
        """Reset service before each test."""
        reset_graph_store()
        reset_graph_service()

    def test_add_entity(self):
        """Test adding an entity."""
        service = get_graph_service()
        node = service.add_entity(
            entity_id="acc1",
            entity_type="account",
            label="Account 1",
            risk_score=0.5,
        )
        assert node.node_id == "acc1"
        assert node.risk_score == 0.5

    def test_link_entities(self):
        """Test linking entities."""
        service = get_graph_service()
        service.add_entity("e1", "entity")
        service.add_entity("e2", "entity")

        edge = service.link_entities("e1", "e2", "linked_to", weight=1.0)
        assert edge is not None
        assert edge.weight == 1.0

    def test_discover_relationships(self):
        """Test discovering relationships."""
        service = get_graph_service()
        for i in range(4):
            service.add_entity(f"e{i}", "entity")

        service.link_entities("e0", "e1")
        service.link_entities("e1", "e2")
        service.link_entities("e2", "e3")

        relationships = service.discover_relationships("e0", max_depth=2)
        assert len(relationships) == 3

    def test_detect_fraud_rings(self):
        """Test detecting fraud rings."""
        service = get_graph_service()
        for i in range(6):
            service.add_entity(f"f{i}", "account")

        service.link_entities("f0", "f1")
        service.link_entities("f1", "f2")
        service.link_entities("f2", "f0")
        service.link_entities("f3", "f4")
        service.link_entities("f4", "f5")

        rings = service.detect_fraud_rings(min_size=3)
        assert len(rings) >= 1

    def test_propagate_risk(self):
        """Test risk propagation through service."""
        service = get_graph_service()
        service.add_entity("r0", "entity", risk_score=0.9)
        service.add_entity("r1", "entity")
        service.add_entity("r2", "entity")

        service.link_entities("r0", "r1")
        service.link_entities("r1", "r2")

        result = service.propagate_risk("r0", max_depth=2)
        assert len(result.affected_nodes) == 3

    def test_analyze_paths(self):
        """Test path analysis."""
        service = get_graph_service()
        for i in range(4):
            service.add_entity(f"p{i}", "entity")

        service.link_entities("p0", "p1", weight=1.0)
        service.link_entities("p1", "p2", weight=2.0)
        service.link_entities("p2", "p3", weight=1.0)

        result = service.analyze_paths("p0", "p3")
        assert result is not None
        assert result.path_length == 3
        assert result.total_weight == 4.0

    def test_get_entity_network(self):
        """Test getting entity network."""
        service = get_graph_service()
        for i in range(5):
            service.add_entity(f"net{i}", "entity")

        service.link_entities("net0", "net1")
        service.link_entities("net0", "net2")
        service.link_entities("net1", "net3")
        service.link_entities("net2", "net4")

        network = service.get_entity_network("net0", depth=2)
        assert len(network["nodes"]) == 5
        assert len(network["edges"]) == 4

    def test_search_by_properties(self):
        """Test searching by properties."""
        service = get_graph_service()
        service.add_entity("s1", "account", properties={"country": "US", "type": "checking"})
        service.add_entity("s2", "account", properties={"country": "UK", "type": "savings"})
        service.add_entity("s3", "account", properties={"country": "US", "type": "savings"})

        results = service.search_by_properties({"country": "US"})
        assert len(results) == 2

    def test_get_graph_statistics(self):
        """Test getting graph statistics."""
        service = get_graph_service()
        for i in range(5):
            service.add_entity(f"stat{i}", "entity")

        for i in range(4):
            service.link_entities(f"stat{i}", f"stat{i+1}")

        stats = service.get_graph_statistics()
        assert stats.total_nodes == 5
        assert stats.total_edges == 4


class TestGraphThreadSafety:
    """Tests for thread safety."""

    def setup_method(self):
        """Reset store before each test."""
        reset_graph_store()

    def test_concurrent_writes(self):
        """Test concurrent write operations."""
        store = get_graph_store()
        errors = []

        def add_nodes(start: int, count: int):
            try:
                for i in range(count):
                    store.add_node(GraphNode(
                        node_id=f"t{start + i}",
                        node_type=NodeType.ENTITY,
                    ))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=add_nodes, args=(i * 10, 10)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        stats = store.get_stats()
        assert stats.total_nodes == 50

    def test_concurrent_reads(self):
        """Test concurrent read operations."""
        store = get_graph_store()
        store.add_node(GraphNode(node_id="read_test", node_type=NodeType.ENTITY))

        results = []

        def read_nodes():
            for _ in range(100):
                result = store.get_node("read_test")
                results.append(result)

        threads = [threading.Thread(target=read_nodes) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 500


class TestGraphIntegration:
    """Integration tests."""

    def setup_method(self):
        """Reset service before each test."""
        reset_graph_store()
        reset_graph_service()

    def test_full_investigation_workflow(self):
        """Test complete fraud investigation workflow."""
        service = get_graph_service()

        # Add accounts
        service.add_entity("acc1", "account", label="Primary Account", risk_score=0.8)
        service.add_entity("acc2", "account", label="Mule Account 1", risk_score=0.6)
        service.add_entity("acc3", "account", label="Mule Account 2", risk_score=0.7)
        service.add_entity("acc4", "account", label="Destination Account", risk_score=0.5)

        # Add IP addresses
        service.add_entity("ip1", "ip_address", label="Fraudster IP")
        service.add_entity("ip2", "ip_address", label="Mule IP 1")

        # Link entities
        service.link_entities("acc1", "ip1", "accessed")
        service.link_entities("acc1", "acc2", "transferred_to")
        service.link_entities("acc2", "acc3", "transferred_to")
        service.link_entities("acc2", "ip2", "accessed")
        service.link_entities("acc3", "acc4", "transferred_to")

        # Discover relationships
        network = service.get_entity_network("acc1", depth=3)
        assert len(network["nodes"]) >= 4

        # Detect fraud rings
        rings = service.detect_fraud_rings(min_size=3)
        assert len(rings) >= 1

        # Propagate risk
        risk = service.propagate_risk("acc1", max_depth=3)
        assert len(risk.affected_nodes) == 6

        # Get statistics
        stats = service.get_graph_statistics()
        assert stats.total_nodes == 6


class TestGraphPerformance:
    """Performance tests."""

    def setup_method(self):
        """Reset store before each test."""
        reset_graph_store()

    def test_bulk_insert_performance(self):
        """Test bulk insert performance."""
        store = get_graph_store()

        start = time.time()
        for i in range(1000):
            store.add_node(GraphNode(
                node_id=f"perf{i}",
                node_type=NodeType.ENTITY,
            ))
        elapsed = time.time() - start

        assert elapsed < 5.0
        assert store.get_stats().total_nodes == 1000

    def test_traversal_performance(self):
        """Test traversal performance."""
        store = get_graph_store()

        for i in range(100):
            store.add_node(GraphNode(node_id=f"trav{i}", node_type=NodeType.ENTITY))
            if i > 0:
                store.add_edge(GraphEdge(source_id=f"trav{i-1}", target_id=f"trav{i}"))

        start = time.time()
        result = store.bfs_traverse("trav0", max_depth=50)
        elapsed = time.time() - start

        assert elapsed < 1.0
        assert len(result) >= 50


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
