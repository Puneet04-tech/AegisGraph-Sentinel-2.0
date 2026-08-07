"""Tests for the GraphStore edge pair index.

`get_edges_between` used to scan every edge in the graph and was called once
per neighbour from inside BFS traversals, making a single lateral-movement
simulation O(V*E). These tests pin the replacement against a brute-force
reference so the index cannot silently diverge from the edge map.
"""

import random
import threading

import pytest

from src.graph_analytics.models import EdgeType, GraphEdge, GraphNode, NodeType
from src.graph_analytics.service import GraphService
from src.graph_analytics.store import GraphStore


def make_node(node_id: str, node_type: NodeType = NodeType.ACCOUNT, **kwargs) -> GraphNode:
    return GraphNode(node_id=node_id, node_type=node_type, **kwargs)


def make_edge(
    edge_id: str,
    source_id: str,
    target_id: str,
    edge_type: EdgeType = EdgeType.SENT_TO,
    weight: float = 1.0,
) -> GraphEdge:
    return GraphEdge(
        edge_id=edge_id,
        source_id=source_id,
        target_id=target_id,
        edge_type=edge_type,
        weight=weight,
    )


def brute_force_edges_between(store: GraphStore, source_id: str, target_id: str):
    """The implementation this PR replaces, kept as the reference oracle."""
    return [
        edge
        for edge in store._edges.values()
        if (edge.source_id == source_id and edge.target_id == target_id)
        or (edge.source_id == target_id and edge.target_id == source_id)
    ]


@pytest.fixture
def store() -> GraphStore:
    return GraphStore()


class TestPairIndexCorrectness:
    def test_matches_brute_force_on_a_randomised_graph(self, store):
        rng = random.Random(7)
        node_ids = [f"n{i}" for i in range(12)]
        for node_id in node_ids:
            store.add_node(make_node(node_id))
        for i in range(120):
            source, target = rng.sample(node_ids, 2)
            store.add_edge(make_edge(f"e{i}", source, target))

        for source in node_ids:
            for target in node_ids:
                expected = brute_force_edges_between(store, source, target)
                actual = store.get_edges_between(source, target)
                assert {e.edge_id for e in actual} == {e.edge_id for e in expected}

    def test_lookup_is_symmetric(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        store.add_edge(make_edge("e1", "a", "b"))

        forward = store.get_edges_between("a", "b")
        backward = store.get_edges_between("b", "a")
        assert [e.edge_id for e in forward] == [e.edge_id for e in backward] == ["e1"]

    def test_returns_every_parallel_edge(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        store.add_edge(make_edge("e1", "a", "b"))
        store.add_edge(make_edge("e2", "b", "a"))
        store.add_edge(make_edge("e3", "a", "b"))

        found = {e.edge_id for e in store.get_edges_between("a", "b")}
        assert found == {"e1", "e2", "e3"}

    def test_unknown_pair_returns_empty_list(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        assert store.get_edges_between("a", "b") == []
        assert store.get_edges_between("ghost", "other") == []

    def test_self_loop_is_indexed(self, store):
        store.add_node(make_node("a"))
        store.add_edge(make_edge("e1", "a", "a"))
        assert [e.edge_id for e in store.get_edges_between("a", "a")] == ["e1"]

    def test_readding_an_edge_id_does_not_duplicate_it(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        for _ in range(4):
            store.add_edge(make_edge("e1", "a", "b"))

        assert [e.edge_id for e in store.get_edges_between("a", "b")] == ["e1"]

    def test_repointing_an_edge_clears_the_old_pair_bucket(self, store):
        for node_id in ("a", "b", "c"):
            store.add_node(make_node(node_id))
        store.add_edge(make_edge("e1", "a", "b"))
        store.add_edge(make_edge("e1", "a", "c"))

        assert store.get_edges_between("a", "b") == []
        assert [e.edge_id for e in store.get_edges_between("a", "c")] == ["e1"]

    def test_clear_empties_the_pair_index(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        store.add_edge(make_edge("e1", "a", "b"))
        store.clear()

        assert store.get_edges_between("a", "b") == []
        assert store._edge_pair_index == {}


class TestIncidentEdges:
    def test_both_endpoints_matches_the_previous_network_filter(self, store):
        for node_id in ("a", "b", "c", "d"):
            store.add_node(make_node(node_id))
        store.add_edge(make_edge("inside", "a", "b"))
        store.add_edge(make_edge("crossing", "b", "d"))

        node_ids = {"a", "b", "c"}
        found = {e.edge_id for e in store.get_incident_edges(node_ids, both_endpoints=True)}
        assert found == {"inside"}

    def test_single_endpoint_keeps_crossing_edges(self, store):
        for node_id in ("a", "b", "c", "d"):
            store.add_node(make_node(node_id))
        store.add_edge(make_edge("inside", "a", "b"))
        store.add_edge(make_edge("crossing", "b", "d"))

        node_ids = {"a", "b", "c"}
        found = {e.edge_id for e in store.get_incident_edges(node_ids, both_endpoints=False)}
        assert found == {"inside", "crossing"}

    def test_empty_node_set_returns_empty(self, store):
        assert store.get_incident_edges(set()) == []

    def test_each_edge_appears_only_once(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        store.add_edge(make_edge("e1", "a", "b"))

        edges = store.get_incident_edges({"a", "b"}, both_endpoints=True)
        assert [e.edge_id for e in edges] == ["e1"]

    def test_self_loop_is_returned_once(self, store):
        store.add_node(make_node("a"))
        store.add_edge(make_edge("e1", "a", "a"))

        edges = store.get_incident_edges({"a"}, both_endpoints=True)
        assert [e.edge_id for e in edges] == ["e1"]


class TestServiceIntegration:
    def test_entity_network_matches_the_previous_full_scan(self, store):
        for node_id in ("a", "b", "c", "d"):
            store.add_node(make_node(node_id))
        store.add_edge(make_edge("e1", "a", "b"))
        store.add_edge(make_edge("e2", "b", "c"))
        store.add_edge(make_edge("e3", "c", "d"))

        service = GraphService(store=store)
        network = service.get_entity_network("a", depth=1)
        node_ids = {n["node_id"] for n in network["nodes"]}
        expected = [
            edge.edge_id
            for edge in store._edges.values()
            if edge.source_id in node_ids and edge.target_id in node_ids
        ]

        assert {e["edge_id"] for e in network["edges"]} == set(expected)

    def test_export_subgraph_matches_the_previous_full_scan(self, store):
        for node_id in ("a", "b", "c", "d"):
            store.add_node(make_node(node_id))
        store.add_edge(make_edge("e1", "a", "b"))
        store.add_edge(make_edge("e2", "b", "c"))
        store.add_edge(make_edge("e3", "c", "d"))

        service = GraphService(store=store)
        exported = service.export_subgraph("a", depth=1)
        node_ids = {n["node_id"] for n in exported["nodes"]}
        expected = [
            edge.edge_id
            for edge in store._edges.values()
            if edge.source_id in node_ids or edge.target_id in node_ids
        ]

        assert {e["edge_id"] for e in exported["edges"]} == set(expected)

    def test_lateral_movement_still_respects_the_weight_threshold(self, store):
        for node_id in ("a", "b", "c"):
            store.add_node(make_node(node_id))
        store.add_edge(make_edge("strong", "a", "b", weight=0.9))
        store.add_edge(make_edge("weak", "b", "c", weight=0.1))

        reachable = store.simulate_lateral_movement("a", max_steps=3, min_weight_threshold=0.5)
        assert set(reachable) == {"a", "b"}


class TestSearchByProperties:
    def test_filters_on_properties(self, store):
        store.add_node(make_node("a", properties={"country": "IN"}))
        store.add_node(make_node("b", properties={"country": "US"}))

        service = GraphService(store=store)
        found = service.search_by_properties({"country": "IN"})
        assert [n.node_id for n in found] == ["a"]

    def test_node_type_restricts_the_candidate_set(self, store):
        store.add_node(make_node("a", NodeType.ACCOUNT, properties={"flag": True}))
        store.add_node(make_node("b", NodeType.DEVICE, properties={"flag": True}))

        service = GraphService(store=store)
        found = service.search_by_properties({"flag": True}, node_type=NodeType.DEVICE.value)
        assert [n.node_id for n in found] == ["b"]

    def test_unknown_node_type_matches_nothing(self, store):
        store.add_node(make_node("a", properties={"flag": True}))

        service = GraphService(store=store)
        assert service.search_by_properties({"flag": True}, node_type="not_a_type") == []

    def test_result_count_is_bounded(self, store):
        for i in range(50):
            store.add_node(make_node(f"n{i}", properties={"flag": True}))

        service = GraphService(store=store)
        assert len(service.search_by_properties({"flag": True}, limit=10)) == 10

    def test_non_positive_limit_returns_empty(self, store):
        store.add_node(make_node("a", properties={"flag": True}))

        service = GraphService(store=store)
        assert service.search_by_properties({"flag": True}, limit=0) == []

    def test_limit_none_returns_everything(self, store):
        for i in range(30):
            store.add_node(make_node(f"n{i}", properties={"flag": True}))

        service = GraphService(store=store)
        assert len(service.search_by_properties({"flag": True}, limit=None)) == 30


class TestConcurrency:
    def test_concurrent_writers_keep_the_index_consistent(self, store):
        node_ids = [f"n{i}" for i in range(30)]
        for node_id in node_ids:
            store.add_node(make_node(node_id))

        def writer(offset: int) -> None:
            for i in range(50):
                source = node_ids[(offset + i) % len(node_ids)]
                target = node_ids[(offset + i + 1) % len(node_ids)]
                store.add_edge(make_edge(f"e{offset}_{i}", source, target))

        threads = [threading.Thread(target=writer, args=(o,)) for o in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        for source in node_ids:
            for target in node_ids:
                expected = {e.edge_id for e in brute_force_edges_between(store, source, target)}
                actual = {e.edge_id for e in store.get_edges_between(source, target)}
                assert actual == expected


class TestTraversalScaling:
    def test_edge_lookup_does_not_scan_the_edge_map(self, store):
        """A pair lookup must not touch edges belonging to other pairs.

        Counting reads of the edge map keeps this stable on shared CI runners,
        where wall-clock assertions are unreliable.
        """
        node_ids = [f"n{i}" for i in range(60)]
        for node_id in node_ids:
            store.add_node(make_node(node_id))
        for i in range(len(node_ids) - 1):
            store.add_edge(make_edge(f"e{i}", node_ids[i], node_ids[i + 1]))

        reads = 0
        real_edges = store._edges

        class CountingEdges(dict):
            def __getitem__(self, key):
                nonlocal reads
                reads += 1
                return real_edges[key]

            def values(self):
                nonlocal reads
                reads += len(real_edges)
                return real_edges.values()

        store._edges = CountingEdges(real_edges)
        try:
            store.get_edges_between("n0", "n1")
        finally:
            store._edges = real_edges

        # Exactly the one edge joining the pair, not the 59 in the graph.
        assert reads == 1
