"""
tests/test_blast_radius.py
==========================

Comprehensive pytest suite for the Blast-Radius Contagion-Score pipeline.

Coverage
--------
Unit tests (BlastRadiusAnalyzer)
  - score_decreases_with_depth         — Sc at depth=2 < Sc at depth=1
  - score_formula_exact_values         — known topology → exact Sc
  - cycle_detection_no_infinite_loop   — circular graph terminates cleanly
  - multi_path_score_accumulation      — two paths to same node sum
  - max_depth_limit_respected          — no nodes beyond the cap appear
  - tier_classification_boundaries     — 0.70 / 0.35 / 0.10 land correctly
  - source_node_not_in_graph_raises    — ValueError propagated
  - undirected_graph_raises_type_error — nx.Graph raises TypeError (direction required)
  - directed_graph_no_upstream_scoring — upstream senders excluded from results
  - zero_score_nodes_excluded          — sub-threshold nodes absent from output
  - hard_max_depth_cap                 — HARD_MAX_DEPTH clamps the input
  - weighted_edges_used                — edge weight != 1.0 changes the score
  - multi_depth_node_accumulates       — node reachable via multiple depths

Integration tests (HTTP / FastAPI)
  - endpoint_returns_200_with_valid_graph
  - endpoint_503_when_graph_not_loaded
  - endpoint_404_when_node_missing
  - endpoint_rejects_depth_over_limit    — 422 Pydantic validation
  - endpoint_rejects_depth_below_limit   — 422 Pydantic validation
  - endpoint_503_when_module_unavailable
  - response_schema_valid                — all required fields present
  - sorted_by_score_descending           — each tier sorted highest-first
"""

from __future__ import annotations

import pytest
import networkx as nx
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Unit-level imports
# ---------------------------------------------------------------------------
from src.features.blast_radius import (
    BlastRadiusAnalyzer,
    BlastRadiusReport,
    ContagionResult,
    TIER_CRITICAL,
    TIER_HIGH,
    TIER_SUSPICIOUS,
    HARD_MAX_DEPTH,
)


# ---------------------------------------------------------------------------
# Shared graph fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def linear_graph() -> nx.DiGraph:
    """
    Simple linear chain:  A → B → C → D (weight=1.0 everywhere)
    Depth from A:  B=1, C=2, D=3
    Sc(B) = 1/1 = 1.0
    Sc(C) = 1/4 = 0.25
    Sc(D) = 1/9 ≈ 0.111
    """
    g = nx.DiGraph()
    g.add_edge("A", "B", weight=1.0)
    g.add_edge("B", "C", weight=1.0)
    g.add_edge("C", "D", weight=1.0)
    return g


@pytest.fixture()
def cyclic_graph() -> nx.DiGraph:
    """
    Cyclic: A → B → C → A  (plus B → D to give something useful)
    """
    g = nx.DiGraph()
    g.add_edge("A", "B", weight=1.0)
    g.add_edge("B", "C", weight=1.0)
    g.add_edge("C", "A", weight=1.0)  # back-edge → cycle
    g.add_edge("B", "D", weight=1.0)
    return g


@pytest.fixture()
def diamond_graph() -> nx.DiGraph:
    """
    Diamond (two paths from A to D):
        A → B → D   (weight=1.0)
        A → C → D   (weight=1.0)
    Sc(B) = 1/1 = 1.0   (depth 1)
    Sc(C) = 1/1 = 1.0   (depth 1)
    Sc(D):
        via B: 1/(2²) = 0.25
        via C: only if C is enqueued, but visited set prevents double-expand;
               however the score is accumulated before enqueue guard applies.
        → Sc(D) = 0.50  (two contributions of 0.25 each)
    """
    g = nx.DiGraph()
    g.add_edge("A", "B", weight=1.0)
    g.add_edge("A", "C", weight=1.0)
    g.add_edge("B", "D", weight=1.0)
    g.add_edge("C", "D", weight=1.0)
    return g


@pytest.fixture()
def weighted_graph() -> nx.DiGraph:
    """
    A → B (weight=2.0)
    A → C (weight=0.5)
    Sc(B) = 2.0 / 1 = 2.0  → CRITICAL
    Sc(C) = 0.5 / 1 = 0.5  → HIGH
    """
    g = nx.DiGraph()
    g.add_edge("A", "B", weight=2.0)
    g.add_edge("A", "C", weight=0.5)
    return g


# ===========================================================================
# UNIT TESTS — BlastRadiusAnalyzer
# ===========================================================================


class TestScoreDecreaseWithDepth:
    def test_deeper_node_has_lower_score(self, linear_graph):
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("A", linear_graph, max_depth=3)

        all_nodes = {r.node_id: r for tier in (report.critical, report.high, report.suspicious) for r in tier}
        # B is depth-1, C is depth-2 — score must decrease
        assert "B" in all_nodes
        assert "C" in all_nodes
        assert all_nodes["B"].contagion_score > all_nodes["C"].contagion_score

    def test_score_halves_correctly(self, linear_graph):
        """Sc(B)=1.0, Sc(C)=0.25 — ratio must be 4x."""
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("A", linear_graph, max_depth=3)

        all_nodes = {r.node_id: r for tier in (report.critical, report.high, report.suspicious) for r in tier}
        sc_b = all_nodes["B"].contagion_score
        sc_c = all_nodes["C"].contagion_score
        assert abs(sc_b - 1.0) < 1e-6
        assert abs(sc_c - 0.25) < 1e-6


class TestScoreFormulaExactValues:
    def test_linear_chain_exact(self, linear_graph):
        """
        A → B → C → D, all weight=1.0, max_depth=3
        Sc(B) = 1/1 = 1.0
        Sc(C) = 1/4 = 0.25
        Sc(D) = 1/9 ≈ 0.1111
        """
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("A", linear_graph, max_depth=3)

        scores = {}
        for tier in (report.critical, report.high, report.suspicious):
            for r in tier:
                scores[r.node_id] = r.contagion_score

        assert abs(scores["B"] - 1.0) < 1e-5
        assert abs(scores["C"] - 0.25) < 1e-5
        assert abs(scores["D"] - (1 / 9)) < 1e-5

    def test_weighted_edge_exact(self, weighted_graph):
        """
        A → B (w=2.0): Sc(B) = 2.0/1² = 2.0
        A → C (w=0.5): Sc(C) = 0.5/1² = 0.5
        """
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("A", weighted_graph, max_depth=1)

        scores = {}
        for tier in (report.critical, report.high, report.suspicious):
            for r in tier:
                scores[r.node_id] = r.contagion_score

        assert abs(scores["B"] - 2.0) < 1e-5
        assert abs(scores["C"] - 0.5) < 1e-5


class TestCycleDetection:
    def test_cyclic_graph_terminates(self, cyclic_graph):
        """Must complete without hanging or raising RecursionError."""
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("A", cyclic_graph, max_depth=5)
        # Should reach B and D at minimum; A itself must NOT appear as a result.
        all_ids = {
            r.node_id
            for tier in (report.critical, report.high, report.suspicious)
            for r in tier
        }
        assert "A" not in all_ids, "Source node must never be scored as a result."
        assert "B" in all_ids

    def test_self_loop_terminates(self):
        """A self-loop must not cause infinite recursion."""
        g = nx.DiGraph()
        g.add_edge("X", "X", weight=1.0)
        g.add_edge("X", "Y", weight=1.0)
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("X", g, max_depth=3)
        all_ids = {
            r.node_id
            for tier in (report.critical, report.high, report.suspicious)
            for r in tier
        }
        assert "X" not in all_ids


class TestMultiPathAccumulation:
    def test_diamond_double_accumulation(self, diamond_graph):
        """
        D is reachable via both B and C at depth-2.
        Sc(D) should be 0.25 + 0.25 = 0.50.
        """
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("A", diamond_graph, max_depth=2)

        scores = {}
        for tier in (report.critical, report.high, report.suspicious):
            for r in tier:
                scores[r.node_id] = r.contagion_score

        assert "D" in scores
        assert abs(scores["D"] - 0.50) < 1e-5

    def test_source_never_in_results(self, diamond_graph):
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("A", diamond_graph, max_depth=3)
        all_ids = {
            r.node_id
            for tier in (report.critical, report.high, report.suspicious)
            for r in tier
        }
        assert "A" not in all_ids


class TestMaxDepthLimit:
    def test_max_depth_1_only_direct_neighbors(self, linear_graph):
        """max_depth=1: only B should be discovered; C and D should not appear."""
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("A", linear_graph, max_depth=1)

        all_ids = {
            r.node_id
            for tier in (report.critical, report.high, report.suspicious)
            for r in tier
        }
        assert "B" in all_ids
        assert "C" not in all_ids
        assert "D" not in all_ids

    def test_max_depth_2_stops_at_two_hops(self, linear_graph):
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("A", linear_graph, max_depth=2)

        all_ids = {
            r.node_id
            for tier in (report.critical, report.high, report.suspicious)
            for r in tier
        }
        assert "C" in all_ids
        assert "D" not in all_ids

    def test_hard_cap_enforced(self, linear_graph):
        """Requesting max_depth > HARD_MAX_DEPTH should silently clamp."""
        analyzer = BlastRadiusAnalyzer()
        # Build a chain long enough to care
        g = nx.DiGraph()
        prev = "ROOT"
        for i in range(HARD_MAX_DEPTH + 5):
            nxt = f"N{i}"
            g.add_edge(prev, nxt, weight=1.0)
            prev = nxt

        report = analyzer.compute("ROOT", g, max_depth=HARD_MAX_DEPTH + 99)
        # All scored nodes must have depth ≤ HARD_MAX_DEPTH
        for tier in (report.critical, report.high, report.suspicious):
            for r in tier:
                assert r.depth <= HARD_MAX_DEPTH, (
                    f"Node {r.node_id!r} at depth {r.depth} exceeds HARD_MAX_DEPTH={HARD_MAX_DEPTH}"
                )


class TestTierClassification:
    def test_critical_threshold(self):
        """A node with Sc exactly at TIER_CRITICAL must land in CRITICAL."""
        g = nx.DiGraph()
        # Weight chosen so Sc = TIER_CRITICAL exactly at depth-1
        g.add_edge("SRC", "TGT", weight=TIER_CRITICAL)
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("SRC", g, max_depth=1)
        assert any(r.node_id == "TGT" for r in report.critical), (
            f"Expected TGT in CRITICAL (Sc={TIER_CRITICAL})"
        )
        assert not any(r.node_id == "TGT" for r in report.high)
        assert not any(r.node_id == "TGT" for r in report.suspicious)

    def test_high_threshold(self):
        """A node with Sc exactly at TIER_HIGH must land in HIGH."""
        g = nx.DiGraph()
        g.add_edge("SRC", "TGT", weight=TIER_HIGH)
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("SRC", g, max_depth=1)
        assert any(r.node_id == "TGT" for r in report.high)
        assert not any(r.node_id == "TGT" for r in report.critical)

    def test_suspicious_threshold(self):
        """A node with Sc exactly at TIER_SUSPICIOUS must land in SUSPICIOUS."""
        g = nx.DiGraph()
        g.add_edge("SRC", "TGT", weight=TIER_SUSPICIOUS)
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("SRC", g, max_depth=1)
        assert any(r.node_id == "TGT" for r in report.suspicious)

    def test_below_threshold_excluded(self):
        """A node below TIER_SUSPICIOUS must NOT appear in any tier."""
        g = nx.DiGraph()
        g.add_edge("SRC", "TGT", weight=0.05)  # 0.05 < 0.10
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("SRC", g, max_depth=1)
        all_ids = {
            r.node_id
            for tier in (report.critical, report.high, report.suspicious)
            for r in tier
        }
        assert "TGT" not in all_ids


class TestErrorHandling:
    def test_missing_source_node_raises(self):
        g = nx.DiGraph()
        g.add_edge("A", "B")
        analyzer = BlastRadiusAnalyzer()
        with pytest.raises(ValueError, match="not found in graph"):
            analyzer.compute("MISSING", g, max_depth=2)

    def test_empty_graph_raises(self):
        g = nx.DiGraph()
        analyzer = BlastRadiusAnalyzer()
        with pytest.raises(ValueError):
            analyzer.compute("ANY", g, max_depth=1)


class TestUndirectedGraph:
    def test_undirected_graph_raises_type_error(self):
        """
        compute() must raise TypeError when passed an undirected nx.Graph.

        Contagion propagates along fund-transfer direction (A → B means B is
        downstream of A).  An undirected graph traverses both directions,
        which would score innocent upstream senders as fraud targets — a
        semantically incorrect and potentially harmful result.
        """
        g = nx.Graph()
        g.add_edge("A", "B", weight=1.0)
        g.add_edge("B", "C", weight=1.0)
        analyzer = BlastRadiusAnalyzer()
        with pytest.raises(TypeError, match="directed graph"):
            analyzer.compute("A", g, max_depth=2)

    def test_directed_graph_does_not_score_upstream_senders(self):
        """
        With a directed graph A → Flagged → C, only C (downstream) must
        appear in results.  A (upstream sender) must not be scored.
        """
        g = nx.DiGraph()
        g.add_edge("A", "Flagged", weight=1.0)
        g.add_edge("Flagged", "C", weight=1.0)
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("Flagged", g, max_depth=2)
        all_ids = {
            r.node_id
            for tier in (report.critical, report.high, report.suspicious)
            for r in tier
        }
        assert "C" in all_ids, "Downstream node C must be scored"
        assert "A" not in all_ids, "Upstream sender A must NOT be scored"
        assert "Flagged" not in all_ids, "Source node must not self-score"


class TestSortOrder:
    def test_each_tier_sorted_highest_score_first(self):
        """
        Build a graph where CRITICAL tier has multiple nodes;
        verify they are returned sorted descending by contagion_score.
        """
        g = nx.DiGraph()
        # Direct edges from SRC with different weights (all land in CRITICAL tier at depth=1)
        g.add_edge("SRC", "N1", weight=1.0)   # Sc = 1.0
        g.add_edge("SRC", "N2", weight=0.9)   # Sc = 0.9
        g.add_edge("SRC", "N3", weight=0.75)  # Sc = 0.75
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("SRC", g, max_depth=1)
        # All should land in CRITICAL (Sc ≥ 0.70)
        assert len(report.critical) == 3
        scores = [r.contagion_score for r in report.critical]
        assert scores == sorted(scores, reverse=True)


class TestWeightedEdges:
    def test_custom_weight_changes_score(self, weighted_graph):
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("A", weighted_graph, max_depth=1)

        scores = {}
        for tier in (report.critical, report.high, report.suspicious):
            for r in tier:
                scores[r.node_id] = r.contagion_score

        # B has weight=2.0 → Sc = 2.0; C has weight=0.5 → Sc = 0.5
        assert abs(scores.get("B", 0) - 2.0) < 1e-5
        assert abs(scores.get("C", 0) - 0.5) < 1e-5

    def test_default_weight_is_one(self):
        """Edges without a weight attribute should default to 1.0."""
        g = nx.DiGraph()
        g.add_edge("A", "B")  # no weight kwarg
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("A", g, max_depth=1)
        all_scores = {
            r.node_id: r.contagion_score
            for tier in (report.critical, report.high, report.suspicious)
            for r in tier
        }
        assert abs(all_scores.get("B", 0) - 1.0) < 1e-5


# ===========================================================================
# INTEGRATION TESTS — FastAPI HTTP layer
# ===========================================================================


from fastapi.testclient import TestClient
from src.api.main import app, state
import src.api.main as api_main


@pytest.fixture()
def api_client():
    """Fresh TestClient without lifespan-side effects."""
    with TestClient(app) as client:
        yield client


@pytest.fixture()
def loaded_graph_state(monkeypatch):
    """
    Inject a minimal in-memory graph into app state so that blast-radius
    requests can succeed without a real Neo4j / file-based graph.
    """
    g = nx.DiGraph()
    g.add_edge("mule_acc_001", "ring_node_A", weight=1.0)
    g.add_edge("ring_node_A", "ring_node_B", weight=0.8)
    g.add_edge("mule_acc_001", "ring_node_C", weight=0.4)
    monkeypatch.setattr(state, "graph_loaded", True)
    monkeypatch.setattr(state, "transaction_graph", g)
    yield g


class TestBlastRadiusEndpointHTTP:

    def test_endpoint_returns_200(self, api_client, loaded_graph_state):
        response = api_client.post(
            "/api/v1/graph/blast-radius",
            json={"node_id": "mule_acc_001", "max_depth": 2},
        )
        assert response.status_code == 200

    def test_response_schema_valid(self, api_client, loaded_graph_state):
        """All required top-level fields must be present."""
        response = api_client.post(
            "/api/v1/graph/blast-radius",
            json={"node_id": "mule_acc_001", "max_depth": 2},
        )
        assert response.status_code == 200
        data = response.json()
        required_fields = {
            "source_node", "max_depth", "total_nodes_evaluated",
            "critical", "high", "suspicious",
            "processing_time_ms", "timestamp",
        }
        assert required_fields.issubset(data.keys()), (
            f"Missing fields: {required_fields - data.keys()}"
        )

    def test_source_node_echoed(self, api_client, loaded_graph_state):
        response = api_client.post(
            "/api/v1/graph/blast-radius",
            json={"node_id": "mule_acc_001", "max_depth": 1},
        )
        data = response.json()
        assert data["source_node"] == "mule_acc_001"
        assert data["max_depth"] == 1

    def test_tiers_are_lists(self, api_client, loaded_graph_state):
        response = api_client.post(
            "/api/v1/graph/blast-radius",
            json={"node_id": "mule_acc_001", "max_depth": 2},
        )
        data = response.json()
        assert isinstance(data["critical"], list)
        assert isinstance(data["high"], list)
        assert isinstance(data["suspicious"], list)

    def test_contagion_node_schema(self, api_client, loaded_graph_state):
        """Every contagion node entry must contain the four expected fields."""
        response = api_client.post(
            "/api/v1/graph/blast-radius",
            json={"node_id": "mule_acc_001", "max_depth": 2},
        )
        data = response.json()
        all_nodes = data["critical"] + data["high"] + data["suspicious"]
        assert len(all_nodes) > 0, "Expected at least some neighbors to be scored."
        for node in all_nodes:
            assert "node_id" in node
            assert "contagion_score" in node
            assert "risk_tier" in node
            assert "depth" in node
            assert node["risk_tier"] in {"CRITICAL", "HIGH", "SUSPICIOUS"}
            assert 0.0 <= node["contagion_score"]
            assert node["depth"] >= 1

    def test_endpoint_503_when_graph_not_loaded(self, api_client, monkeypatch):
        monkeypatch.setattr(state, "graph_loaded", False)
        monkeypatch.setattr(state, "transaction_graph", None)
        response = api_client.post(
            "/api/v1/graph/blast-radius",
            json={"node_id": "any_node", "max_depth": 2},
        )
        assert response.status_code == 503

    def test_endpoint_404_when_node_missing(self, api_client, loaded_graph_state):
        response = api_client.post(
            "/api/v1/graph/blast-radius",
            json={"node_id": "ghost_node_xyz", "max_depth": 2},
        )
        assert response.status_code == 404

    def test_endpoint_rejects_depth_over_limit(self, api_client, loaded_graph_state):
        """max_depth > 5 must fail with 422 (Pydantic validation)."""
        response = api_client.post(
            "/api/v1/graph/blast-radius",
            json={"node_id": "mule_acc_001", "max_depth": 6},
        )
        assert response.status_code == 422

    def test_endpoint_rejects_depth_below_limit(self, api_client, loaded_graph_state):
        """max_depth < 1 must fail with 422 (Pydantic validation)."""
        response = api_client.post(
            "/api/v1/graph/blast-radius",
            json={"node_id": "mule_acc_001", "max_depth": 0},
        )
        assert response.status_code == 422

    def test_endpoint_rejects_missing_node_id(self, api_client, loaded_graph_state):
        """Omitting node_id entirely must fail with 422."""
        response = api_client.post(
            "/api/v1/graph/blast-radius",
            json={"max_depth": 2},
        )
        assert response.status_code == 422

    def test_endpoint_503_when_module_unavailable(
        self, api_client, loaded_graph_state, monkeypatch
    ):
        """If BlastRadiusAnalyzer itself is unavailable, return 503."""
        monkeypatch.setattr(api_main, "BLAST_RADIUS_AVAILABLE", False)
        monkeypatch.setattr(api_main, "BlastRadiusAnalyzer", None)
        response = api_client.post(
            "/api/v1/graph/blast-radius",
            json={"node_id": "mule_acc_001", "max_depth": 2},
        )
        assert response.status_code == 503

    def test_tiers_sorted_descending(self, api_client, loaded_graph_state):
        """Each tier list must be sorted by contagion_score descending."""
        response = api_client.post(
            "/api/v1/graph/blast-radius",
            json={"node_id": "mule_acc_001", "max_depth": 2},
        )
        data = response.json()
        for tier_key in ("critical", "high", "suspicious"):
            tier_list = data[tier_key]
            scores = [n["contagion_score"] for n in tier_list]
            assert scores == sorted(scores, reverse=True), (
                f"Tier '{tier_key}' is not sorted descending: {scores}"
            )

    def test_processing_time_is_positive(self, api_client, loaded_graph_state):
        response = api_client.post(
            "/api/v1/graph/blast-radius",
            json={"node_id": "mule_acc_001", "max_depth": 2},
        )
        data = response.json()
        assert data["processing_time_ms"] >= 0.0

    def test_timestamp_is_utc_iso(self, api_client, loaded_graph_state):
        """Timestamp should end with 'Z' (UTC ISO-8601)."""
        response = api_client.post(
            "/api/v1/graph/blast-radius",
            json={"node_id": "mule_acc_001", "max_depth": 2},
        )
        data = response.json()
        assert data["timestamp"].endswith("Z")

    def test_total_nodes_evaluated_matches_tiers(self, api_client, loaded_graph_state):
        """total_nodes_evaluated must equal the total across all tiers."""
        response = api_client.post(
            "/api/v1/graph/blast-radius",
            json={"node_id": "mule_acc_001", "max_depth": 2},
        )
        data = response.json()
        total_in_tiers = (
            len(data["critical"]) + len(data["high"]) + len(data["suspicious"])
        )
        assert data["total_nodes_evaluated"] == total_in_tiers


# ===========================================================================
# Score-degradation math across depth — regression suite
# ===========================================================================


class TestScoreDegradationMath:
    """
    Verify the exact quadratic degradation formula across increasing depths.
    All edges have weight=1.0 for simplicity.

    Expected Sc values (w=1.0):
        depth 1  → 1 / 1²  = 1.000000  → CRITICAL  (≥0.70)
        depth 2  → 1 / 2²  = 0.250000  → SUSPICIOUS (≥0.10)
        depth 3  → 1 / 3²  ≈ 0.111111  → SUSPICIOUS (≥0.10)
        depth 4  → 1 / 4²  = 0.062500  → BELOW threshold (excluded)
        depth 5  → 1 / 5²  = 0.040000  → BELOW threshold (excluded)

    Depths 4 and 5 produce Sc < 0.10 (the SUSPICIOUS floor), so they are
    correctly absent from the response payload — this is the expected behavior.
    """

    EXPECTED_IN_RESULTS = {
        1: 1.0,
        2: 0.25,
        3: 1 / 9,
    }

    EXPECTED_BELOW_THRESHOLD = {4, 5}  # Sc < 0.10 → excluded

    @pytest.fixture()
    def long_chain(self) -> nx.DiGraph:
        g = nx.DiGraph()
        nodes = ["ROOT"] + [f"D{i}" for i in range(1, 6)]
        for u, v in zip(nodes, nodes[1:]):
            g.add_edge(u, v, weight=1.0)
        return g

    @pytest.mark.parametrize("depth", [1, 2, 3])
    def test_score_at_depth_within_threshold(self, long_chain, depth):
        """Depths 1–3 should appear in results with the correct exact Sc value."""
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("ROOT", long_chain, max_depth=depth)
        all_nodes = {
            r.node_id: r
            for tier in (report.critical, report.high, report.suspicious)
            for r in tier
        }
        node_id = f"D{depth}"
        assert node_id in all_nodes, (
            f"D{depth} (depth={depth}) not found in results; "
            f"only found: {list(all_nodes)}"
        )
        expected_sc = self.EXPECTED_IN_RESULTS[depth]
        actual_sc = all_nodes[node_id].contagion_score
        assert abs(actual_sc - expected_sc) < 1e-6, (
            f"Sc({node_id}) = {actual_sc:.8f}, expected {expected_sc:.8f}"
        )

    @pytest.mark.parametrize("depth", [4, 5])
    def test_score_at_depth_below_threshold_excluded(self, long_chain, depth):
        """
        Depths 4–5 yield Sc < 0.10 and must NOT appear in any tier
        (they are correctly filtered out by the detection threshold).
        """
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("ROOT", long_chain, max_depth=depth)
        all_ids = {
            r.node_id
            for tier in (report.critical, report.high, report.suspicious)
            for r in tier
        }
        node_id = f"D{depth}"
        assert node_id not in all_ids, (
            f"D{depth} should be below the detection threshold (Sc < 0.10) "
            f"and absent from results, but was found."
        )

    def test_score_strictly_decreasing_along_observable_chain(self, long_chain):
        """Score must decrease monotonically for the 3 observable depths (1–3)."""
        analyzer = BlastRadiusAnalyzer()
        report = analyzer.compute("ROOT", long_chain, max_depth=3)
        all_nodes = {
            r.node_id: r.contagion_score
            for tier in (report.critical, report.high, report.suspicious)
            for r in tier
        }
        for d in range(1, 3):
            n_cur, n_nxt = f"D{d}", f"D{d + 1}"
            assert all_nodes.get(n_cur, 0) > all_nodes.get(n_nxt, 0), (
                f"Score at depth {d} ({all_nodes.get(n_cur)}) not > "
                f"score at depth {d + 1} ({all_nodes.get(n_nxt)})"
            )

