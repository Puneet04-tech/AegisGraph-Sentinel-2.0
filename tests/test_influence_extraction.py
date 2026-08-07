"""Influential-neighbour ranking must reflect the graph, not a constant.

`_get_influential_neighbors` attached `'influence_score': 0.5` to every
neighbour and returned them in edge-index order, so any downstream sort by
influence was a no-op and the set an analyst saw next to a blocked transaction
was determined by internal tensor ordering. The relationship label was the
literal `'CONNECTED'` for every edge.

This feeds the Aegis-Oracle explanation surface the project documents as
analyst-facing, so the ranking decides which account gets investigated next.
"""

from __future__ import annotations

import pytest
import torch

from src.inference.production_scorer import ProductionRiskScorer


def scorer() -> ProductionRiskScorer:
    """A scorer instance without constructing the model or executor."""
    return ProductionRiskScorer.__new__(ProductionRiskScorer)


def subgraph(
    edges,
    node_ids=None,
    edge_types=None,
    edge_attr=None,
    node_risk=None,
    edge_type_names=None,
):
    """Build a minimal subgraph dict of the shape the scorer consumes."""
    node_ids = node_ids or ["ACC0", "ACC1", "ACC2", "ACC3", "ACC4"]
    idx_to_node_id = dict(enumerate(node_ids))
    node_id_to_idx = {v: k for k, v in idx_to_node_id.items()}

    edge_index = torch.tensor(
        [[s for s, _ in edges], [t for _, t in edges]], dtype=torch.long
    ) if edges else torch.zeros((2, 0), dtype=torch.long)

    payload = {
        "idx_to_node_id": idx_to_node_id,
        "node_id_to_idx": node_id_to_idx,
        "edge_index": edge_index,
        "edge_attr": (
            torch.tensor(edge_attr, dtype=torch.float)
            if edge_attr is not None
            else torch.zeros((0,), dtype=torch.float)
        ),
    }
    if edge_types is not None:
        payload["edge_type"] = torch.tensor(edge_types, dtype=torch.long)
    if node_risk is not None:
        payload["node_risk"] = node_risk
    if edge_type_names is not None:
        payload["edge_type_names"] = edge_type_names
    return payload


# ACC0 connected to ACC1..ACC4.
STAR_EDGES = [(0, 1), (0, 2), (0, 3), (0, 4)]


class TestScoresAreNoLongerConstant:
    """The defect this PR exists for."""

    def test_attention_produces_varying_scores(self):
        graph = subgraph(STAR_EDGES)
        weights = torch.tensor([0.1, 0.9, 0.4, 0.2])
        edge_index = graph["edge_index"]

        result = scorer()._get_influential_neighbors(
            "ACC0", graph, top_k=5,
            attention_weights=weights, attention_edge_index=edge_index,
        )

        scores = [item["influence_score"] for item in result]
        assert len(set(scores)) > 1, "still behaving like a constant"
        assert scores != [0.5] * len(scores)

    def test_ranking_follows_attention(self):
        graph = subgraph(STAR_EDGES)
        # ACC2 (edge 1) is by far the most attended.
        weights = torch.tensor([0.1, 0.9, 0.4, 0.2])

        result = scorer()._get_influential_neighbors(
            "ACC0", graph, top_k=5,
            attention_weights=weights, attention_edge_index=graph["edge_index"],
        )

        assert result[0]["node_id"] == "ACC2"
        assert result[-1]["node_id"] == "ACC1"

    def test_results_are_sorted_descending(self):
        graph = subgraph(STAR_EDGES)
        weights = torch.tensor([0.3, 0.9, 0.1, 0.6])

        result = scorer()._get_influential_neighbors(
            "ACC0", graph, top_k=5,
            attention_weights=weights, attention_edge_index=graph["edge_index"],
        )

        scores = [item["influence_score"] for item in result]
        assert scores == sorted(scores, reverse=True)

    def test_the_ranking_is_not_edge_index_order(self):
        """The old implementation returned whatever came first in the tensor."""
        graph = subgraph(STAR_EDGES)
        # Deliberately inverted: the last edge is the most influential.
        weights = torch.tensor([0.1, 0.2, 0.3, 0.9])

        result = scorer()._get_influential_neighbors(
            "ACC0", graph, top_k=5,
            attention_weights=weights, attention_edge_index=graph["edge_index"],
        )

        assert [item["node_id"] for item in result] == ["ACC4", "ACC3", "ACC2", "ACC1"]

    def test_scores_are_normalised_into_the_unit_range(self):
        graph = subgraph(STAR_EDGES)
        # Raw attention magnitudes vary with subgraph size; normalisation makes
        # influence comparable across transactions.
        weights = torch.tensor([10.0, 90.0, 40.0, 20.0])

        result = scorer()._get_influential_neighbors(
            "ACC0", graph, top_k=5,
            attention_weights=weights, attention_edge_index=graph["edge_index"],
        )

        assert all(0.0 <= item["influence_score"] <= 1.0 for item in result)
        assert result[0]["influence_score"] == pytest.approx(1.0)

    def test_ordering_is_stable_across_calls(self):
        graph = subgraph(STAR_EDGES)
        weights = torch.tensor([0.5, 0.5, 0.5, 0.5])
        instance = scorer()

        first = [
            item["node_id"]
            for item in instance._get_influential_neighbors(
                "ACC0", graph, top_k=5,
                attention_weights=weights, attention_edge_index=graph["edge_index"],
            )
        ]
        second = [
            item["node_id"]
            for item in instance._get_influential_neighbors(
                "ACC0", graph, top_k=5,
                attention_weights=weights, attention_edge_index=graph["edge_index"],
            )
        ]
        assert first == second


class TestMultiHeadAttention:
    def test_heads_are_averaged(self):
        graph = subgraph(STAR_EDGES)
        # Two heads per edge; ACC3 (edge 2) wins on the mean.
        weights = torch.tensor(
            [[0.1, 0.1], [0.2, 0.2], [0.9, 0.9], [0.3, 0.3]]
        )

        result = scorer()._get_influential_neighbors(
            "ACC0", graph, top_k=5,
            attention_weights=weights, attention_edge_index=graph["edge_index"],
        )
        assert result[0]["node_id"] == "ACC3"


class TestStructuralFallback:
    def test_used_when_the_model_exposes_no_attention(self):
        graph = subgraph(
            STAR_EDGES,
            edge_attr=[[1.0], [9.0], [4.0], [2.0]],
        )

        result = scorer()._get_influential_neighbors("ACC0", graph, top_k=5)

        scores = [item["influence_score"] for item in result]
        assert len(set(scores)) > 1
        assert result[0]["node_id"] == "ACC2"

    def test_neighbour_risk_raises_influence(self):
        graph = subgraph(STAR_EDGES, node_risk=[0.0, 0.1, 0.95, 0.2, 0.3])

        result = scorer()._get_influential_neighbors("ACC0", graph, top_k=5)
        assert result[0]["node_id"] == "ACC2"

    def test_unbounded_edge_features_are_squashed(self):
        graph = subgraph(STAR_EDGES, edge_attr=[[1e9], [1.0], [1.0], [1.0]])

        result = scorer()._get_influential_neighbors("ACC0", graph, top_k=5)
        assert all(0.0 <= item["influence_score"] <= 1.0 for item in result)

    def test_malformed_node_risk_is_ignored(self):
        graph = subgraph(STAR_EDGES, node_risk=["not-a-number"] * 5)
        result = scorer()._get_influential_neighbors("ACC0", graph, top_k=5)
        assert all(0.0 <= item["influence_score"] <= 1.0 for item in result)


class TestRelationshipLabels:
    def test_the_real_edge_type_is_reported(self):
        graph = subgraph(
            STAR_EDGES,
            edge_types=[0, 1, 2, 1],
            edge_type_names=["TRANSFER", "LOGIN", "WITHDRAWAL"],
        )

        result = scorer()._get_influential_neighbors("ACC0", graph, top_k=5)
        labels = {item["node_id"]: item["relationship"] for item in result}

        assert labels["ACC1"] == "TRANSFER"
        assert labels["ACC2"] == "LOGIN"
        assert labels["ACC3"] == "WITHDRAWAL"

    def test_an_unnamed_edge_type_falls_back_to_its_id(self):
        graph = subgraph(STAR_EDGES, edge_types=[7, 7, 7, 7])
        result = scorer()._get_influential_neighbors("ACC0", graph, top_k=5)
        assert all(item["relationship"] == "EDGE_TYPE_7" for item in result)

    def test_no_edge_types_falls_back_to_connected(self):
        graph = subgraph(STAR_EDGES)
        result = scorer()._get_influential_neighbors("ACC0", graph, top_k=5)
        assert all(item["relationship"] == "CONNECTED" for item in result)

    def test_an_out_of_range_type_index_falls_back(self):
        graph = subgraph(
            STAR_EDGES, edge_types=[0, 1, 2, 3], edge_type_names=["TRANSFER"]
        )
        result = scorer()._get_influential_neighbors("ACC0", graph, top_k=5)
        labels = {item["relationship"] for item in result}
        assert "TRANSFER" in labels
        assert "EDGE_TYPE_3" in labels


class TestDegenerateGraphs:
    def test_a_node_absent_from_the_subgraph_returns_empty(self):
        graph = subgraph(STAR_EDGES)
        assert scorer()._get_influential_neighbors("GHOST", graph, top_k=5) == []

    def test_an_isolated_node_returns_empty(self):
        graph = subgraph([(1, 2), (2, 3)])
        assert scorer()._get_influential_neighbors("ACC0", graph, top_k=5) == []

    def test_an_edgeless_graph_returns_empty(self):
        graph = subgraph([])
        assert scorer()._get_influential_neighbors("ACC0", graph, top_k=5) == []

    def test_self_loops_are_not_reported_as_neighbours(self):
        graph = subgraph([(0, 0), (0, 1)])
        result = scorer()._get_influential_neighbors("ACC0", graph, top_k=5)
        assert [item["node_id"] for item in result] == ["ACC1"]

    def test_incoming_edges_are_followed_as_well_as_outgoing(self):
        graph = subgraph([(1, 0), (2, 0)])
        result = scorer()._get_influential_neighbors("ACC0", graph, top_k=5)
        assert {item["node_id"] for item in result} == {"ACC1", "ACC2"}

    def test_parallel_edges_yield_one_entry_per_neighbour(self):
        """A pair joined by several edges is one neighbour."""
        graph = subgraph([(0, 1), (0, 1), (0, 1)])
        result = scorer()._get_influential_neighbors("ACC0", graph, top_k=5)
        assert len(result) == 1
        assert result[0]["node_id"] == "ACC1"

    def test_parallel_edges_rank_by_the_strongest_connection(self):
        graph = subgraph([(0, 1), (0, 1), (0, 2)])
        weights = torch.tensor([0.1, 0.9, 0.5])

        result = scorer()._get_influential_neighbors(
            "ACC0", graph, top_k=5,
            attention_weights=weights, attention_edge_index=graph["edge_index"],
        )
        assert result[0]["node_id"] == "ACC1"

    def test_fewer_neighbours_than_top_k(self):
        graph = subgraph([(0, 1)])
        assert len(scorer()._get_influential_neighbors("ACC0", graph, top_k=5)) == 1

    def test_top_k_truncates(self):
        graph = subgraph(STAR_EDGES)
        assert len(scorer()._get_influential_neighbors("ACC0", graph, top_k=2)) == 2

    def test_an_unknown_neighbour_index_is_labelled(self):
        graph = subgraph([(0, 9)], node_ids=["ACC0", "ACC1"])
        result = scorer()._get_influential_neighbors("ACC0", graph, top_k=5)
        assert result[0]["node_id"] == "UNKNOWN"


class TestAttentionEdgeCases:
    def test_empty_attention_tensors_fall_back(self):
        graph = subgraph(STAR_EDGES)
        result = scorer()._get_influential_neighbors(
            "ACC0", graph, top_k=5,
            attention_weights=torch.zeros(0),
            attention_edge_index=torch.zeros((2, 0), dtype=torch.long),
        )
        assert len(result) == 4

    def test_all_zero_attention_falls_back(self):
        graph = subgraph(STAR_EDGES)
        result = scorer()._get_influential_neighbors(
            "ACC0", graph, top_k=5,
            attention_weights=torch.zeros(4),
            attention_edge_index=graph["edge_index"],
        )
        assert len(result) == 4
        assert all(0.0 <= item["influence_score"] <= 1.0 for item in result)

    def test_attention_covering_only_some_edges(self):
        """Attention shorter than the edge list must not index out of range."""
        graph = subgraph(STAR_EDGES)
        result = scorer()._get_influential_neighbors(
            "ACC0", graph, top_k=5,
            attention_weights=torch.tensor([0.9, 0.5]),
            attention_edge_index=graph["edge_index"][:, :2],
        )
        assert len(result) == 4

    def test_reversed_pair_orientation_is_matched(self):
        """Attention may report (dst, src) for an edge stored as (src, dst)."""
        graph = subgraph([(0, 1)])
        reversed_index = torch.tensor([[1], [0]], dtype=torch.long)

        result = scorer()._get_influential_neighbors(
            "ACC0", graph, top_k=5,
            attention_weights=torch.tensor([0.8]),
            attention_edge_index=reversed_index,
        )
        assert result[0]["influence_score"] == pytest.approx(1.0)

    def test_missing_attention_arguments_use_the_fallback(self):
        graph = subgraph(STAR_EDGES, edge_attr=[[1.0], [5.0], [2.0], [3.0]])
        result = scorer()._get_influential_neighbors(
            "ACC0", graph, top_k=5,
            attention_weights=None, attention_edge_index=graph["edge_index"],
        )
        assert len(result) == 4
