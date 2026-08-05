"""Tests for incrementally maintained GraphStore statistics.

The store previously recomputed every aggregate on each write by walking the
whole adjacency map, making ingestion quadratic. These tests pin the two
properties that replacement has to preserve: the incremental counters must
agree with a full recomputation at all times, and repeated writes of the same
element must not inflate any count.
"""

import random
import threading

import pytest

from src.graph_analytics.models import EdgeType, GraphEdge, GraphNode, NodeType
from src.graph_analytics.store import GraphStore


def make_node(node_id: str, node_type: NodeType = NodeType.ACCOUNT) -> GraphNode:
    return GraphNode(node_id=node_id, node_type=node_type)


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


def brute_force_degree(store: GraphStore) -> int:
    """Reference implementation of the counter the store maintains."""
    return sum(len(neighbors) for neighbors in store._adjacency.values())


@pytest.fixture
def store() -> GraphStore:
    return GraphStore()


class TestIncrementalCounters:
    def test_total_degree_matches_brute_force_after_inserts(self, store):
        for i in range(20):
            store.add_node(make_node(f"n{i}"))
        for i in range(19):
            store.add_edge(make_edge(f"e{i}", f"n{i}", f"n{i + 1}"))

        assert store._total_degree == brute_force_degree(store)

    def test_counters_track_randomised_insert_and_remove_sequence(self, store):
        rng = random.Random(1234)
        node_ids = [f"n{i}" for i in range(15)]
        for node_id in node_ids:
            store.add_node(make_node(node_id))

        live_edges = []
        for step in range(200):
            if live_edges and rng.random() < 0.4:
                edge_id = rng.choice(live_edges)
                live_edges.remove(edge_id)
                store.remove_edge(edge_id)
            else:
                edge_id = f"e{step}"
                source, target = rng.sample(node_ids, 2)
                store.add_edge(make_edge(edge_id, source, target))
                live_edges.append(edge_id)

            assert store._total_degree == brute_force_degree(store), (
                f"counter drifted at step {step}"
            )

    def test_average_degree_matches_full_recomputation(self, store):
        for i in range(10):
            store.add_node(make_node(f"n{i}"))
        for i in range(9):
            store.add_edge(make_edge(f"e{i}", f"n{i}", f"n{i + 1}"))

        incremental = store.get_stats().average_degree
        store.recompute_total_degree()
        assert store.get_stats().average_degree == pytest.approx(incremental)

    def test_recompute_total_degree_returns_current_value(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        store.add_edge(make_edge("e1", "a", "b"))

        assert store.recompute_total_degree() == brute_force_degree(store)


class TestIdempotentWrites:
    def test_readding_same_node_does_not_inflate_type_counts(self, store):
        for _ in range(5):
            store.add_node(make_node("a", NodeType.ACCOUNT))

        stats = store.get_stats()
        assert stats.total_nodes == 1
        assert stats.node_types[NodeType.ACCOUNT.value] == 1
        assert len(store.get_nodes_by_type(NodeType.ACCOUNT)) == 1

    def test_readding_same_edge_does_not_inflate_degree(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        for _ in range(5):
            store.add_edge(make_edge("e1", "a", "b"))

        assert store.get_stats().total_edges == 1
        assert store._total_degree == brute_force_degree(store) == 1

    def test_changing_node_type_moves_it_between_buckets(self, store):
        store.add_node(make_node("a", NodeType.ACCOUNT))
        store.add_node(make_node("a", NodeType.DEVICE))

        stats = store.get_stats()
        assert stats.total_nodes == 1
        assert NodeType.ACCOUNT.value not in stats.node_types
        assert stats.node_types[NodeType.DEVICE.value] == 1
        assert store.get_nodes_by_type(NodeType.ACCOUNT) == []
        assert len(store.get_nodes_by_type(NodeType.DEVICE)) == 1

    def test_changing_edge_type_moves_it_between_buckets(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        store.add_edge(make_edge("e1", "a", "b", EdgeType.SENT_TO))
        store.add_edge(make_edge("e1", "a", "b", EdgeType.ACCESSED))

        stats = store.get_stats()
        assert stats.total_edges == 1
        assert EdgeType.SENT_TO.value not in stats.edge_types
        assert stats.edge_types[EdgeType.ACCESSED.value] == 1

    def test_repointing_an_edge_releases_the_old_adjacency(self, store):
        for node_id in ("a", "b", "c"):
            store.add_node(make_node(node_id))
        store.add_edge(make_edge("e1", "a", "b"))
        store.add_edge(make_edge("e1", "a", "c"))

        assert store._total_degree == brute_force_degree(store)
        assert store._adjacency["a"] == {"c"}


class TestRemoval:
    def test_remove_edge_restores_prior_stats(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        before = store.get_stats()
        baseline = (before.total_edges, before.average_degree, before.graph_density)

        store.add_edge(make_edge("e1", "a", "b"))
        store.remove_edge("e1")

        after = store.get_stats()
        assert (after.total_edges, after.average_degree, after.graph_density) == baseline
        assert store._total_degree == brute_force_degree(store) == 0

    def test_parallel_edges_keep_adjacency_until_the_last_is_removed(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        store.add_edge(make_edge("e1", "a", "b"))
        store.add_edge(make_edge("e2", "a", "b"))

        store.remove_edge("e1")
        assert store._adjacency["a"] == {"b"}
        assert store._total_degree == brute_force_degree(store) == 1

        store.remove_edge("e2")
        assert "a" not in store._adjacency
        assert store._total_degree == brute_force_degree(store) == 0

    def test_remove_node_drops_every_incident_edge(self, store):
        for node_id in ("a", "b", "c"):
            store.add_node(make_node(node_id))
        store.add_edge(make_edge("e1", "a", "b"))
        store.add_edge(make_edge("e2", "b", "c"))
        store.add_edge(make_edge("e3", "c", "a"))

        assert store.remove_node("b") is True

        stats = store.get_stats()
        assert stats.total_nodes == 2
        assert stats.total_edges == 1
        assert store.get_edge("e1") is None
        assert store.get_edge("e2") is None
        assert store.get_edge("e3") is not None
        assert store._total_degree == brute_force_degree(store)

    def test_remove_node_evicts_the_cached_copy(self, store):
        store.add_node(make_node("a"))
        assert store.get_node("a") is not None

        store.remove_node("a")
        assert store.get_node("a") is None

    def test_removing_absent_elements_reports_false(self, store):
        assert store.remove_edge("missing") is False
        assert store.remove_node("missing") is False

    def test_self_loop_is_counted_and_removed_cleanly(self, store):
        store.add_node(make_node("a"))
        store.add_edge(make_edge("e1", "a", "a"))

        assert store._total_degree == brute_force_degree(store) == 1

        store.remove_edge("e1")
        assert store._total_degree == brute_force_degree(store) == 0


class TestStatsSemantics:
    def test_empty_store_reports_zeroed_stats(self, store):
        stats = store.get_stats()
        assert stats.total_nodes == 0
        assert stats.total_edges == 0
        assert stats.average_degree == 0.0
        assert stats.graph_density == 0.0

    def test_single_node_has_zero_density(self, store):
        store.add_node(make_node("a"))
        assert store.get_stats().graph_density == 0.0

    def test_density_matches_the_documented_formula(self, store):
        for node_id in ("a", "b", "c"):
            store.add_node(make_node(node_id))
        store.add_edge(make_edge("e1", "a", "b"))
        store.add_edge(make_edge("e2", "b", "c"))

        assert store.get_stats().graph_density == pytest.approx(2 / (3 * 2))

    def test_clear_resets_every_counter(self, store):
        store.add_node(make_node("a"))
        store.add_node(make_node("b"))
        store.add_edge(make_edge("e1", "a", "b"))
        store.clear()

        stats = store.get_stats()
        assert stats.total_nodes == 0
        assert stats.total_edges == 0
        assert stats.node_types == {}
        assert stats.edge_types == {}
        assert store._total_degree == 0
        assert store._pair_edge_count == {}


class TestConcurrency:
    def test_concurrent_writers_keep_counters_consistent(self, store):
        node_ids = [f"n{i}" for i in range(40)]
        for node_id in node_ids:
            store.add_node(make_node(node_id))

        def writer(offset: int) -> None:
            for i in range(60):
                source = node_ids[(offset + i) % len(node_ids)]
                target = node_ids[(offset + i + 1) % len(node_ids)]
                store.add_edge(make_edge(f"e{offset}_{i}", source, target))

        threads = [threading.Thread(target=writer, args=(o,)) for o in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert store._total_degree == brute_force_degree(store)
        assert store.get_stats().total_edges == 8 * 60


class TestIngestionScaling:
    @pytest.mark.parametrize("size", [200, 400])
    def test_writes_never_trigger_a_full_recomputation(self, size, monkeypatch):
        """Writes must not walk the adjacency map.

        Counting `_update_stats` calls rather than wall time keeps this
        assertion stable on shared CI runners: the old implementation invoked
        it once per write, so ingesting N elements cost N adjacency walks.
        """
        store = GraphStore()
        calls = 0
        original = GraphStore._update_stats

        def counting_update(self):
            nonlocal calls
            calls += 1
            return original(self)

        monkeypatch.setattr(GraphStore, "_update_stats", counting_update)

        for i in range(size):
            store.add_node(make_node(f"n{i}"))
        for i in range(size - 1):
            store.add_edge(make_edge(f"e{i}", f"n{i}", f"n{i + 1}"))

        assert calls == 0, "writes should only mark stats dirty, never recompute"

        stats = store.get_stats()
        assert calls == 1, "the first read should recompute exactly once"
        assert stats.total_nodes == size
        assert stats.total_edges == size - 1

        store.get_stats()
        assert calls == 1, "a second read with no writes between should reuse the cache"
        assert store._total_degree == brute_force_degree(store)
