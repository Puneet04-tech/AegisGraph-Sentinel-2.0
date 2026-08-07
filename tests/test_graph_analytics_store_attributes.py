"""Regression tests for GraphStore attribute initialisation.

`GraphStore` referenced ``_edge_pair_index``, ``_graph_version`` and the
centrality memoisation attributes from its read paths without ever
initialising or maintaining them, so every edge-pair query and every
centrality computation raised ``AttributeError`` and edge-pair queries would
have silently returned empty lists even if the attributes existed. These tests
exercise the full add -> query -> remove path plus memoisation invalidation.
"""

import pytest

from src.graph_analytics.models import EdgeType, GraphEdge, GraphNode, NodeType
from src.graph_analytics.store import GraphStore


def make_node(node_id: str, node_type: NodeType = NodeType.ACCOUNT, **kwargs) -> GraphNode:
    return GraphNode(node_id=node_id, node_type=node_type, **kwargs)


def make_edge(
    edge_id: str,
    source_id: str,
    target_id: str,
    edge_type: EdgeType = EdgeType.SENT_TO,
    weight: float = 0.9,
) -> GraphEdge:
    return GraphEdge(
        edge_id=edge_id,
        source_id=source_id,
        target_id=target_id,
        edge_type=edge_type,
        weight=weight,
    )


@pytest.fixture
def store() -> GraphStore:
    return GraphStore()


class TestGraphStoreAttributeInitialisation:
    def test_full_read_write_path(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        store.add_edge(make_edge("e1", "a", "b"))

        assert [e.edge_id for e in store.get_edges_between("a", "b")] == ["e1"]
        assert {e.edge_id for e in store.get_incident_edges({"a", "b"})} == {"e1"}

        store.remove_edge("e1")
        assert store.get_edges_between("a", "b") == []
        assert store.get_incident_edges({"a", "b"}) == []

    def test_centrality_and_lateral_movement_no_attribute_error(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        store.add_node(make_node("c"))
        store.add_edge(make_edge("e1", "a", "b"))
        store.add_edge(make_edge("e2", "b", "c"))

        metrics = store.calculate_centrality("a")
        assert metrics.node_id == "a"
        assert metrics.degree_centrality == pytest.approx(0.5)

        moved = store.simulate_lateral_movement("a", min_weight_threshold=0.5)
        assert set(moved) == {"a", "b", "c"}

    def test_graph_version_bumps_on_every_mutation(self, store):
        assert store._graph_version == 0
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        store.add_edge(make_edge("e1", "a", "b"))
        store.remove_edge("e1")
        store.remove_node("a")
        store.clear()
        assert store._graph_version >= 5

    def test_centrality_memoisation_is_invalidated_by_mutation(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        store.add_edge(make_edge("e1", "a", "b"))

        first = store.calculate_all_centralities()
        assert store._centrality_cache_key is not None
        second = store.calculate_all_centralities()
        assert second == first
        assert store._centrality_cache is not None

        store.add_node(make_node("c"))

        refreshed = store.calculate_all_centralities()
        assert "c" in refreshed
        assert set(refreshed) == {"a", "b", "c"}
        # The mutation bumped the graph version, so the stale memoised result
        # was replaced rather than replayed.
        assert store._centrality_cache_key == (store._graph_version, None)

    def test_clear_resets_centrality_cache(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        store.add_edge(make_edge("e1", "a", "b"))
        store.calculate_all_centralities()
        assert store._centrality_cache is not None

        store.clear()
        assert store._centrality_cache is None
        assert store._centrality_cache_key is None
        assert store._edge_pair_index == {}
