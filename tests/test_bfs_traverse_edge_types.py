"""GraphStore.bfs_traverse must respect the edge_types filter (Issue #3511).

``bfs_traverse`` accepted an ``edge_types`` argument but ignored it, walking
every adjacency edge regardless of type. These tests pin the filtered
traversal: a node reachable only through a disallowed edge type must not be
visited, while a type-homogeneous chain traverses normally.
"""

import pytest

from src.graph_analytics.models import EdgeType, GraphEdge, GraphNode, NodeType
from src.graph_analytics.store import GraphStore


@pytest.fixture
def store() -> GraphStore:
    return GraphStore()


@pytest.fixture
def mixed_graph(store):
    """n0 -> n1 via SENT_TO, n1 -> n2 via RECEIVED_FROM, n0 -> n3 via SENT_TO."""
    for i in range(4):
        store.add_node(GraphNode(node_id=f"n{i}", node_type=NodeType.ENTITY))
    store.add_edge(
        GraphEdge(source_id="n0", target_id="n1", edge_type=EdgeType.SENT_TO)
    )
    store.add_edge(
        GraphEdge(source_id="n1", target_id="n2", edge_type=EdgeType.RECEIVED_FROM)
    )
    store.add_edge(
        GraphEdge(source_id="n0", target_id="n3", edge_type=EdgeType.SENT_TO)
    )
    return store


class TestBfsTraverseEdgeTypes:
    def test_sent_to_only_skips_received_from_hop(self, mixed_graph):
        result = mixed_graph.bfs_traverse("n0", max_depth=3, edge_types=[EdgeType.SENT_TO])
        ids = {node.node_id for node in result}
        # n1 and n3 are reached via SENT_TO; n2 requires the RECEIVED_FROM edge.
        assert ids == {"n0", "n1", "n3"}
        assert "n2" not in ids

    def test_all_edge_types_traverses_entire_graph(self, mixed_graph):
        result = mixed_graph.bfs_traverse(
            "n0", max_depth=3, edge_types=[EdgeType.SENT_TO, EdgeType.RECEIVED_FROM]
        )
        ids = {node.node_id for node in result}
        assert ids == {"n0", "n1", "n2", "n3"}

    def test_received_from_only_excludes_sent_to_neighbors(self, mixed_graph):
        result = mixed_graph.bfs_traverse("n0", max_depth=2, edge_types=[EdgeType.RECEIVED_FROM])
        ids = {node.node_id for node in result}
        assert ids == {"n0"}

    def test_no_filter_matches_default_behaviour(self, store):
        store.add_node(GraphNode(node_id="a", node_type=NodeType.ENTITY))
        store.add_node(GraphNode(node_id="b", node_type=NodeType.ENTITY))
        store.add_edge(GraphEdge(source_id="a", target_id="b"))
        result = store.bfs_traverse("a", max_depth=2)
        assert {node.node_id for node in result} == {"a", "b"}
