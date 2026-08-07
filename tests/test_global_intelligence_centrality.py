"""Centrality and structural metrics in the global intelligence engine.

Four measures here were degree-based approximations wearing different names,
one of which (`closeness`) divided a value by itself and was therefore constant,
while `eigenvector` returned `len(neighbours) / 10` and could exceed 1.0. The
network diameter never inspected an edge and the clustering coefficient was a
hardcoded 0.0. These tests validate the replacements against known graphs.
"""

from __future__ import annotations

import pytest

from src.global_intelligence.network_analysis import NetworkAnalysisEngine


class FakeEdge:
    def __init__(self, source_id: str, target_id: str):
        self.source_id = source_id
        self.target_id = target_id
        self.relationship_type = "linked_to"


class FakeStore:
    """Minimal stand-in exposing only what the engine reads."""

    def __init__(self, pairs, extra_nodes=()):
        self._graph_nodes = {}
        self._edges_by_node = {}

        for source, target in pairs:
            for node_id in (source, target):
                self._graph_nodes.setdefault(node_id, object())
                self._edges_by_node.setdefault(node_id, [])
            edge = FakeEdge(source, target)
            self._edges_by_node[source].append(edge)
            self._edges_by_node[target].append(edge)

        for node_id in extra_nodes:
            self._graph_nodes.setdefault(node_id, object())
            self._edges_by_node.setdefault(node_id, [])

    def get_node_edges(self, node_id):
        return self._edges_by_node.get(node_id, [])


def engine_for(pairs, extra_nodes=()):
    engine = NetworkAnalysisEngine.__new__(NetworkAnalysisEngine)
    engine._store = FakeStore(pairs, extra_nodes)
    engine._graph = None
    engine._config = None
    engine._centrality_cache = None
    engine._centrality_cache_key = None
    return engine


# a-b-c-d-e: b, c, d lie on paths; a and e are leaves.
PATH = [("a", "b"), ("b", "c"), ("c", "d"), ("d", "e")]
STAR = [("hub", "l1"), ("hub", "l2"), ("hub", "l3"), ("hub", "l4")]
COMPLETE = [("a", "b"), ("a", "c"), ("a", "d"), ("b", "c"), ("b", "d"), ("c", "d")]
TRIANGLE = [("a", "b"), ("b", "c"), ("a", "c")]


class TestClosenessIsNoLongerConstant:
    def test_closeness_varies_across_a_path(self):
        """The replaced implementation returned len(n)/len(n) -- always 1.0."""
        engine = engine_for(PATH)
        scores = {n: engine._calculate_closeness(n) for n in "abcde"}
        assert len(set(round(v, 6) for v in scores.values())) > 1

    def test_the_middle_of_a_path_is_closest(self):
        engine = engine_for(PATH)
        assert engine._calculate_closeness("c") > engine._calculate_closeness("b")
        assert engine._calculate_closeness("b") > engine._calculate_closeness("a")

    def test_path_closeness_matches_hand_computed_values(self):
        engine = engine_for(PATH)
        # c reaches all 4 others at distances 2+1+1+2 = 6.
        assert engine._calculate_closeness("c") == pytest.approx(4 / 6)
        # a reaches all 4 at distances 1+2+3+4 = 10.
        assert engine._calculate_closeness("a") == pytest.approx(4 / 10)

    def test_isolated_node_scores_zero(self):
        engine = engine_for(PATH, extra_nodes=["lonely"])
        assert engine._calculate_closeness("lonely") == 0.0

    def test_stays_within_unit_range(self):
        engine = engine_for(STAR)
        for node in ("hub", "l1", "l2", "l3", "l4"):
            assert 0.0 <= engine._calculate_closeness(node) <= 1.0


class TestEigenvectorIsBounded:
    def test_stays_within_unit_range_for_a_high_degree_hub(self):
        """The replaced implementation returned len(neighbours) / 10, which
        exceeds 1.0 above ten neighbours."""
        pairs = [("hub", f"l{i}") for i in range(25)]
        engine = engine_for(pairs)

        assert engine._calculate_eigenvector("hub") <= 1.0
        assert engine._calculate_eigenvector("hub") == pytest.approx(1.0)
        for i in range(25):
            assert 0.0 <= engine._calculate_eigenvector(f"l{i}") <= 1.0

    def test_complete_graph_is_symmetric(self):
        engine = engine_for(COMPLETE)
        scores = [engine._calculate_eigenvector(n) for n in "abcd"]
        assert all(s == pytest.approx(scores[0]) for s in scores)

    def test_central_node_outranks_a_leaf(self):
        engine = engine_for(PATH)
        assert engine._calculate_eigenvector("c") > engine._calculate_eigenvector("a")


class TestBetweennessIsNotDegree:
    def test_star_hub_carries_every_path(self):
        engine = engine_for(STAR)
        assert engine._calculate_betweenness("hub") == pytest.approx(1.0)
        assert engine._calculate_betweenness("l1") == pytest.approx(0.0)

    def test_path_matches_hand_computed_values(self):
        engine = engine_for(PATH)
        # Raw pair counts 0, 3, 4, 3, 0 normalised by (n-1)(n-2)/2 = 6.
        assert engine._calculate_betweenness("c") == pytest.approx(4 / 6)
        assert engine._calculate_betweenness("b") == pytest.approx(3 / 6)
        assert engine._calculate_betweenness("a") == pytest.approx(0.0)

    def test_complete_graph_has_no_bridges(self):
        """Degree centrality is maximal here; betweenness must be zero."""
        engine = engine_for(COMPLETE)
        for node in "abcd":
            assert engine._calculate_betweenness(node) == pytest.approx(0.0)

    def test_distinguishes_a_bridge_from_an_equal_degree_leaf(self):
        pairs = [("a", "b"), ("b", "c"), ("c", "d"), ("b", "e"), ("c", "f")]
        engine = engine_for(pairs)
        assert engine._calculate_betweenness("b") > engine._calculate_betweenness("a")
        assert engine._calculate_betweenness("c") > engine._calculate_betweenness("d")

    def test_sample_size_is_honoured_and_approximates_the_exact_result(self):
        """The parameter was previously accepted and ignored entirely."""
        pairs = [(f"n{i}", f"n{i + 1}") for i in range(19)]
        engine = engine_for(pairs)

        exact = engine._calculate_betweenness("n10", sample_size=1000)
        engine._centrality_cache = None
        engine._centrality_cache_key = None
        sampled = engine._calculate_betweenness("n10", sample_size=10)

        assert sampled == pytest.approx(exact, abs=0.35)

    def test_stays_within_unit_range(self):
        engine = engine_for(PATH)
        for node in "abcde":
            assert 0.0 <= engine._calculate_betweenness(node) <= 1.0


class TestPageRank:
    def test_is_not_a_raw_degree_ratio(self):
        engine = engine_for(STAR)
        assert engine._calculate_pagerank("hub") > engine._calculate_pagerank("l1")

    def test_sums_to_one_across_the_graph(self):
        engine = engine_for(PATH)
        total = sum(engine._calculate_pagerank(n) for n in "abcde")
        assert total == pytest.approx(1.0)

    def test_complete_graph_is_uniform_by_symmetry(self):
        engine = engine_for(COMPLETE)
        for node in "abcd":
            assert engine._calculate_pagerank(node) == pytest.approx(0.25)

    def test_unknown_node_scores_zero(self):
        engine = engine_for(PATH)
        assert engine._calculate_pagerank("ghost") == 0.0


class TestCombinedMetrics:
    def test_calculate_centrality_populates_every_field(self):
        engine = engine_for(PATH)
        metrics = engine.calculate_centrality("c")

        assert metrics.node_id == "c"
        assert metrics.degree_centrality > 0
        assert metrics.betweenness_centrality > 0
        assert metrics.closeness_centrality > 0
        assert metrics.eigenvector_centrality > 0
        assert metrics.pagerank > 0

    def test_the_four_measures_are_not_all_identical(self):
        """They were all degree centrality under different names."""
        engine = engine_for(PATH)
        metrics = engine.calculate_centrality("b")
        values = {
            round(metrics.betweenness_centrality, 6),
            round(metrics.closeness_centrality, 6),
            round(metrics.eigenvector_centrality, 6),
            round(metrics.pagerank, 6),
        }
        assert len(values) > 1

    def test_results_are_cached_between_calls(self):
        engine = engine_for(PATH)
        first = engine._all_centralities()
        assert engine._all_centralities() is first


class TestDiameter:
    def _network(self, nodes):
        class FakeNetwork:
            pass

        network = FakeNetwork()
        network.nodes = nodes
        return network

    def test_path_diameter(self):
        engine = engine_for(PATH)
        assert engine._estimate_diameter(self._network(list("abcde"))) == 4

    def test_star_diameter(self):
        engine = engine_for(STAR)
        network = self._network(["hub", "l1", "l2", "l3", "l4"])
        assert engine._estimate_diameter(network) == 2

    def test_complete_graph_diameter_is_one(self):
        engine = engine_for(COMPLETE)
        assert engine._estimate_diameter(self._network(list("abcd"))) == 1

    def test_single_node_diameter_is_zero(self):
        engine = engine_for(PATH)
        assert engine._estimate_diameter(self._network(["a"])) == 0

    def test_empty_network_diameter_is_zero(self):
        engine = engine_for(PATH)
        assert engine._estimate_diameter(self._network([])) == 0

    def test_diameter_depends_on_shape_not_node_count(self):
        """The replaced version returned min(5, len(nodes)//5 + 1), so a path
        and a star of the same size were indistinguishable."""
        path_engine = engine_for(PATH)
        star_engine = engine_for(STAR)

        path_diameter = path_engine._estimate_diameter(self._network(list("abcde")))
        star_diameter = star_engine._estimate_diameter(
            self._network(["hub", "l1", "l2", "l3", "l4"])
        )
        assert path_diameter != star_diameter

    def test_edges_leaving_the_network_do_not_inflate_it(self):
        pairs = PATH + [("e", "outsider")]
        engine = engine_for(pairs)
        assert engine._estimate_diameter(self._network(list("abcde"))) == 4


class TestClusteringCoefficient:
    def test_triangle_scores_one(self):
        from src.global_intelligence.knowledge_graph import KnowledgeGraphEngine

        engine = KnowledgeGraphEngine.__new__(KnowledgeGraphEngine)
        nodes = {n: object() for n in "abc"}
        edges = {f"e{i}": FakeEdge(s, t) for i, (s, t) in enumerate(TRIANGLE)}

        assert engine._average_clustering(nodes, edges) == pytest.approx(1.0)

    def test_star_scores_zero(self):
        from src.global_intelligence.knowledge_graph import KnowledgeGraphEngine

        engine = KnowledgeGraphEngine.__new__(KnowledgeGraphEngine)
        nodes = {n: object() for n in ["hub", "l1", "l2", "l3", "l4"]}
        edges = {f"e{i}": FakeEdge(s, t) for i, (s, t) in enumerate(STAR)}

        assert engine._average_clustering(nodes, edges) == pytest.approx(0.0)

    def test_graph_too_small_scores_zero(self):
        from src.global_intelligence.knowledge_graph import KnowledgeGraphEngine

        engine = KnowledgeGraphEngine.__new__(KnowledgeGraphEngine)
        nodes = {n: object() for n in "ab"}
        edges = {"e0": FakeEdge("a", "b")}

        assert engine._average_clustering(nodes, edges) == 0.0

    def test_edges_to_unknown_nodes_are_ignored(self):
        from src.global_intelligence.knowledge_graph import KnowledgeGraphEngine

        engine = KnowledgeGraphEngine.__new__(KnowledgeGraphEngine)
        nodes = {n: object() for n in "abc"}
        edges = {f"e{i}": FakeEdge(s, t) for i, (s, t) in enumerate(TRIANGLE)}
        edges["ghost"] = FakeEdge("a", "not_in_graph")

        assert engine._average_clustering(nodes, edges) == pytest.approx(1.0)
