"""Tests for the graph centrality algorithms.

`calculate_centrality` used to return hardcoded constants for four of its five
measures, and its PageRank depended only on node count — so it was identical for
every node and any ranking built on it was arbitrary. These tests validate each
measure against hand-computed values on graphs whose centralities are known.
"""

import pytest

from src.graph_analytics.centrality import (
    all_centralities,
    average_clustering_coefficient,
    betweenness_centrality,
    closeness_centrality,
    degree_centrality,
    eigenvector_centrality,
    graph_diameter,
    pagerank,
)
from src.graph_analytics.models import EdgeType, GraphEdge, GraphNode, NodeType
from src.graph_analytics.service import GraphService
from src.graph_analytics.store import GraphStore


def undirected(pairs):
    """Build an adjacency mapping from undirected edge pairs."""
    adjacency = {}
    for source, target in pairs:
        adjacency.setdefault(source, set()).add(target)
        adjacency.setdefault(target, set()).add(source)
    return adjacency


# A path graph a-b-c-d-e: b, c, d lie on paths, a and e are leaves.
PATH_PAIRS = [("a", "b"), ("b", "c"), ("c", "d"), ("d", "e")]
PATH_NODES = ["a", "b", "c", "d", "e"]

# A star with `hub` at the centre and four leaves.
STAR_PAIRS = [("hub", "l1"), ("hub", "l2"), ("hub", "l3"), ("hub", "l4")]
STAR_NODES = ["hub", "l1", "l2", "l3", "l4"]

# Complete graph on four nodes: every node is interchangeable.
COMPLETE_PAIRS = [
    ("a", "b"), ("a", "c"), ("a", "d"),
    ("b", "c"), ("b", "d"), ("c", "d"),
]
COMPLETE_NODES = ["a", "b", "c", "d"]

# Two disconnected triangles.
SPLIT_PAIRS = [("a", "b"), ("b", "c"), ("a", "c"), ("x", "y"), ("y", "z"), ("x", "z")]
SPLIT_NODES = ["a", "b", "c", "x", "y", "z"]


class TestDegreeCentrality:
    def test_star_hub_is_fully_connected(self):
        scores = degree_centrality(undirected(STAR_PAIRS), STAR_NODES)
        assert scores["hub"] == pytest.approx(1.0)
        assert scores["l1"] == pytest.approx(0.25)

    def test_single_node_graph_is_zero(self):
        assert degree_centrality({}, ["only"]) == {"only": 0.0}

    def test_empty_graph_returns_empty(self):
        assert degree_centrality({}, []) == {}


class TestBetweennessCentrality:
    def test_path_graph_matches_hand_computed_values(self):
        scores = betweenness_centrality(undirected(PATH_PAIRS), PATH_NODES)
        # On a 5-node path the raw pair counts are a=0, b=3, c=4, d=3, e=0,
        # normalised by (n-1)(n-2)/2 = 6.
        assert scores["a"] == pytest.approx(0.0)
        assert scores["b"] == pytest.approx(3 / 6)
        assert scores["c"] == pytest.approx(4 / 6)
        assert scores["d"] == pytest.approx(3 / 6)
        assert scores["e"] == pytest.approx(0.0)

    def test_star_hub_carries_every_path(self):
        scores = betweenness_centrality(undirected(STAR_PAIRS), STAR_NODES)
        assert scores["hub"] == pytest.approx(1.0)
        for leaf in ("l1", "l2", "l3", "l4"):
            assert scores[leaf] == pytest.approx(0.0)

    def test_complete_graph_has_no_bridges(self):
        scores = betweenness_centrality(undirected(COMPLETE_PAIRS), COMPLETE_NODES)
        for value in scores.values():
            assert value == pytest.approx(0.0)

    def test_distinguishes_a_bridge_from_a_leaf(self):
        """The property degree centrality cannot express."""
        pairs = [("a", "b"), ("b", "c"), ("c", "d"), ("b", "e"), ("c", "f")]
        nodes = ["a", "b", "c", "d", "e", "f"]
        scores = betweenness_centrality(undirected(pairs), nodes)
        assert scores["b"] > scores["a"]
        assert scores["c"] > scores["d"]

    def test_disconnected_components_score_independently(self):
        scores = betweenness_centrality(undirected(SPLIT_PAIRS), SPLIT_NODES)
        for value in scores.values():
            assert value == pytest.approx(0.0)

    def test_sampling_approximates_the_exact_result(self):
        pairs = [(f"n{i}", f"n{i + 1}") for i in range(19)]
        nodes = [f"n{i}" for i in range(20)]
        adjacency = undirected(pairs)

        exact = betweenness_centrality(adjacency, nodes)
        sampled = betweenness_centrality(adjacency, nodes, sample_size=10)

        # Same shape: the middle of the path still dominates the ends.
        assert sampled["n10"] > sampled["n1"]
        assert sampled["n10"] == pytest.approx(exact["n10"], abs=0.35)

    def test_sample_size_of_zero_returns_zeroes(self):
        scores = betweenness_centrality(undirected(PATH_PAIRS), PATH_NODES, sample_size=0)
        assert all(value == 0.0 for value in scores.values())

    def test_scores_stay_within_unit_range(self):
        scores = betweenness_centrality(undirected(PATH_PAIRS), PATH_NODES)
        assert all(0.0 <= value <= 1.0 for value in scores.values())

    def test_two_node_graph_is_zero(self):
        scores = betweenness_centrality(undirected([("a", "b")]), ["a", "b"])
        assert scores == {"a": 0.0, "b": 0.0}


class TestClosenessCentrality:
    def test_is_not_constant(self):
        """The replaced implementation divided a value by itself, so every
        connected node scored exactly 1.0."""
        scores = closeness_centrality(undirected(PATH_PAIRS), PATH_NODES)
        assert len(set(round(v, 6) for v in scores.values())) > 1

    def test_path_graph_matches_hand_computed_values(self):
        scores = closeness_centrality(undirected(PATH_PAIRS), PATH_NODES)
        # Node c reaches all 4 others with distances 2+1+1+2 = 6.
        assert scores["c"] == pytest.approx(4 / 6)
        # Node a reaches all 4 with distances 1+2+3+4 = 10.
        assert scores["a"] == pytest.approx(4 / 10)
        assert scores["c"] > scores["b"] > scores["a"]

    def test_star_hub_is_closest(self):
        scores = closeness_centrality(undirected(STAR_PAIRS), STAR_NODES)
        assert scores["hub"] == pytest.approx(1.0)
        assert scores["hub"] > scores["l1"]

    def test_isolated_node_scores_zero(self):
        adjacency = undirected(PATH_PAIRS)
        nodes = PATH_NODES + ["lonely"]
        scores = closeness_centrality(adjacency, nodes)
        assert scores["lonely"] == 0.0

    def test_component_size_is_penalised(self):
        """A node central in a small component must not outrank the main graph."""
        pairs = [("a", "b"), ("b", "c"), ("c", "d"), ("d", "e"), ("x", "y")]
        nodes = ["a", "b", "c", "d", "e", "x", "y"]
        scores = closeness_centrality(undirected(pairs), nodes)
        assert scores["c"] > scores["x"]

    def test_scores_stay_within_unit_range(self):
        scores = closeness_centrality(undirected(SPLIT_PAIRS), SPLIT_NODES)
        assert all(0.0 <= value <= 1.0 for value in scores.values())


class TestPageRank:
    def test_sums_to_one(self):
        ranks = pagerank(undirected(PATH_PAIRS), PATH_NODES)
        assert sum(ranks.values()) == pytest.approx(1.0)

    def test_is_not_uniform(self):
        """The replaced implementation returned 1/n for every node."""
        ranks = pagerank(undirected(STAR_PAIRS), STAR_NODES)
        assert len(set(round(v, 6) for v in ranks.values())) > 1
        assert ranks["hub"] > ranks["l1"]

    def test_complete_graph_is_uniform_by_symmetry(self):
        ranks = pagerank(undirected(COMPLETE_PAIRS), COMPLETE_NODES)
        for value in ranks.values():
            assert value == pytest.approx(0.25)

    def test_dangling_node_mass_is_not_lost(self):
        # c only receives, so its rank would leak without redistribution.
        adjacency = {"a": {"b"}, "b": {"c"}}
        ranks = pagerank(adjacency, ["a", "b", "c"])
        assert sum(ranks.values()) == pytest.approx(1.0)
        assert ranks["c"] > ranks["a"]

    def test_single_node_holds_all_rank(self):
        assert pagerank({}, ["only"]) == {"only": 1.0}

    def test_empty_graph_returns_empty(self):
        assert pagerank({}, []) == {}

    def test_no_edges_is_uniform(self):
        ranks = pagerank({}, ["a", "b", "c", "d"])
        for value in ranks.values():
            assert value == pytest.approx(0.25)


class TestEigenvectorCentrality:
    def test_stays_within_unit_range(self):
        """The replaced implementation returned len(neighbours) / 10, which
        exceeded 1.0 for any node with more than ten neighbours."""
        pairs = [("hub", f"l{i}") for i in range(25)]
        nodes = ["hub"] + [f"l{i}" for i in range(25)]
        scores = eigenvector_centrality(undirected(pairs), nodes)
        assert all(0.0 <= value <= 1.0 for value in scores.values())
        assert scores["hub"] == pytest.approx(1.0)

    def test_complete_graph_is_symmetric(self):
        scores = eigenvector_centrality(undirected(COMPLETE_PAIRS), COMPLETE_NODES)
        for value in scores.values():
            assert value == pytest.approx(1.0)

    def test_well_connected_node_outranks_a_leaf(self):
        scores = eigenvector_centrality(undirected(PATH_PAIRS), PATH_NODES)
        assert scores["c"] > scores["a"]

    def test_edgeless_graph_scores_zero(self):
        scores = eigenvector_centrality({}, ["a", "b", "c"])
        assert all(value == 0.0 for value in scores.values())

    def test_single_node_scores_zero(self):
        assert eigenvector_centrality({}, ["only"]) == {"only": 0.0}


class TestStructuralMeasures:
    def test_diameter_of_a_path(self):
        assert graph_diameter(undirected(PATH_PAIRS), PATH_NODES) == 4

    def test_diameter_of_a_star(self):
        assert graph_diameter(undirected(STAR_PAIRS), STAR_NODES) == 2

    def test_diameter_of_a_single_node(self):
        assert graph_diameter({}, ["only"]) == 0

    def test_clustering_of_a_triangle_is_one(self):
        pairs = [("a", "b"), ("b", "c"), ("a", "c")]
        assert average_clustering_coefficient(undirected(pairs), ["a", "b", "c"]) == pytest.approx(1.0)

    def test_clustering_of_a_star_is_zero(self):
        assert average_clustering_coefficient(undirected(STAR_PAIRS), STAR_NODES) == pytest.approx(0.0)

    def test_clustering_of_a_tiny_graph_is_zero(self):
        assert average_clustering_coefficient(undirected([("a", "b")]), ["a", "b"]) == 0.0


class TestSelfLoopsAndMalformedInput:
    def test_self_loops_do_not_inflate_degree(self):
        adjacency = {"a": {"a", "b"}, "b": {"a"}}
        scores = degree_centrality(adjacency, ["a", "b"])
        assert scores["a"] == pytest.approx(1.0)

    def test_edges_to_unknown_nodes_are_ignored(self):
        adjacency = {"a": {"b", "ghost"}}
        scores = degree_centrality(adjacency, ["a", "b"])
        assert scores["a"] == pytest.approx(1.0)

    def test_all_centralities_returns_every_measure(self):
        scored = all_centralities(undirected(PATH_PAIRS), PATH_NODES)
        assert set(scored) == set(PATH_NODES)
        for values in scored.values():
            assert set(values) == {
                "degree_centrality",
                "betweenness_centrality",
                "closeness_centrality",
                "page_rank",
                "eigen_centrality",
            }


class TestStoreIntegration:
    @pytest.fixture
    def store(self):
        store = GraphStore()
        for node_id in PATH_NODES:
            store.add_node(GraphNode(node_id=node_id, node_type=NodeType.ACCOUNT))
        for i, (source, target) in enumerate(PATH_PAIRS):
            store.add_edge(
                GraphEdge(
                    edge_id=f"e{i}",
                    source_id=source,
                    target_id=target,
                    edge_type=EdgeType.SENT_TO,
                    weight=1.0,
                )
            )
        return store

    def test_page_rank_is_no_longer_constant(self, store):
        ranks = {
            node_id: store.calculate_centrality(node_id).page_rank
            for node_id in PATH_NODES
        }
        assert len(set(round(v, 6) for v in ranks.values())) > 1

    def test_betweenness_is_populated(self, store):
        assert store.calculate_centrality("c").betweenness_centrality > 0.0

    def test_closeness_is_populated(self, store):
        assert store.calculate_centrality("c").closeness_centrality > 0.0

    def test_eigen_centrality_is_populated(self, store):
        assert store.calculate_centrality("c").eigen_centrality > 0.0

    def test_unknown_node_returns_zeroed_metrics(self, store):
        metrics = store.calculate_centrality("ghost")
        assert metrics.node_id == "ghost"
        assert metrics.page_rank == 0.0

    def test_single_node_store_returns_zeroed_metrics(self):
        store = GraphStore()
        store.add_node(GraphNode(node_id="only", node_type=NodeType.ACCOUNT))
        assert store.calculate_centrality("only").page_rank == 0.0

    def test_results_are_cached_until_the_graph_changes(self, store):
        first = store.calculate_all_centralities()
        assert store.calculate_all_centralities() is first

        store.add_node(GraphNode(node_id="f", node_type=NodeType.ACCOUNT))
        assert store.calculate_all_centralities() is not first

    def test_clear_invalidates_the_cache(self, store):
        store.calculate_all_centralities()
        store.clear()
        assert store.calculate_all_centralities() == {}

    def test_critical_entities_are_ranked_meaningfully(self, store):
        service = GraphService(store=store)
        critical = service.find_critical_entities(min_centrality=0.1)

        assert critical, "expected the path graph to yield critical entities"
        # c is the most central node of a 5-node path by every measure.
        assert critical[0].node_id == "c"

    def test_critical_entities_ordering_is_stable(self, store):
        service = GraphService(store=store)
        first = [m.node_id for m in service.find_critical_entities()]
        second = [m.node_id for m in service.find_critical_entities()]
        assert first == second

    def test_critical_entities_on_an_empty_store(self):
        service = GraphService(store=GraphStore())
        assert service.find_critical_entities() == []
