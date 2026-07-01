"""Tests for route optimisation engine."""

import pytest

from src.route_optimization import (
    LocationHistory,
    RouteEdge,
    RouteOptimizationEngine,
    Waypoint,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _wp(node_id: str, lat: float = 0.0, lon: float = 0.0) -> Waypoint:
    return Waypoint(node_id=node_id, lat=lat, lon=lon)


def _edge(frm: str, to: str, dist: float = 100.0, time: float = 10.0, cong: float = 1.0) -> RouteEdge:
    return RouteEdge(from_id=frm, to_id=to, distance_m=dist, travel_time_s=time, congestion_factor=cong)


def _build_linear_graph() -> RouteOptimizationEngine:
    """A -> B -> C -> D, all edges with cost 10."""
    eng = RouteOptimizationEngine()
    for nid in ("A", "B", "C", "D"):
        eng.add_waypoint(_wp(nid))
    for frm, to in [("A", "B"), ("B", "C"), ("C", "D")]:
        eng.add_edge(_edge(frm, to))
    return eng


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class TestModels:
    def test_route_edge_effective_time(self):
        edge = _edge("A", "B", time=10.0, cong=2.0)
        assert edge.effective_time_s == 20.0

    def test_route_to_dict(self):
        from src.route_optimization.models import Route
        r = Route(waypoints=[_wp("A"), _wp("B")], total_distance_m=500.0, total_time_s=60.0)
        d = r.to_dict()
        assert d["stops"] == ["A", "B"]
        assert d["total_distance_m"] == 500.0


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

class TestGraphConstruction:
    def test_add_waypoint(self):
        eng = RouteOptimizationEngine()
        eng.add_waypoint(_wp("X"))
        stats = eng.get_stats()
        assert stats["total_waypoints"] == 1

    def test_add_edge_unknown_node_raises(self):
        eng = RouteOptimizationEngine()
        eng.add_waypoint(_wp("A"))
        with pytest.raises(ValueError):
            eng.add_edge(_edge("A", "Z"))

    def test_stats_after_setup(self):
        eng = _build_linear_graph()
        stats = eng.get_stats()
        assert stats["total_waypoints"] == 4
        assert stats["total_edges"] == 3


# ---------------------------------------------------------------------------
# Route optimisation
# ---------------------------------------------------------------------------

class TestRouteOptimisation:
    def test_direct_route(self):
        eng = _build_linear_graph()
        route = eng.find_optimal_route("A", "B")
        assert route is not None
        assert [w.node_id for w in route.waypoints] == ["A", "B"]

    def test_multi_hop_route(self):
        eng = _build_linear_graph()
        route = eng.find_optimal_route("A", "D")
        assert route is not None
        assert [w.node_id for w in route.waypoints] == ["A", "B", "C", "D"]
        assert route.total_time_s == pytest.approx(30.0)

    def test_no_path_returns_none(self):
        eng = _build_linear_graph()
        # No reverse edges, so D->A has no path
        assert eng.find_optimal_route("D", "A") is None

    def test_unknown_node_returns_none(self):
        eng = _build_linear_graph()
        assert eng.find_optimal_route("A", "Z") is None

    def test_prefers_lower_effective_time(self):
        """Two paths A->C: direct (high congestion) vs A->B->C (low congestion)."""
        eng = RouteOptimizationEngine()
        for nid in ("A", "B", "C"):
            eng.add_waypoint(_wp(nid))
        # Direct A->C: 10s * 5x congestion = 50s effective
        eng.add_edge(RouteEdge("A", "C", distance_m=100, travel_time_s=10.0, congestion_factor=5.0))
        # Via B: 10s + 10s = 20s effective
        eng.add_edge(_edge("A", "B", time=10.0))
        eng.add_edge(_edge("B", "C", time=10.0))

        route = eng.find_optimal_route("A", "C")
        assert route is not None
        assert [w.node_id for w in route.waypoints] == ["A", "B", "C"]

    def test_total_distance_positive(self):
        eng = RouteOptimizationEngine()
        eng.add_waypoint(Waypoint("A", lat=0.0, lon=0.0))
        eng.add_waypoint(Waypoint("B", lat=1.0, lon=1.0))
        eng.add_edge(RouteEdge("A", "B", distance_m=157_000, travel_time_s=600))
        route = eng.find_optimal_route("A", "B")
        assert route is not None
        assert route.total_distance_m > 0


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

class TestPrediction:
    def _engine_with_history(self) -> RouteOptimizationEngine:
        eng = _build_linear_graph()
        # Asset visited A->B->C five times and A->B->D once
        for _ in range(5):
            eng.record_history(LocationHistory("asset1", ["A", "B", "C"]))
        eng.record_history(LocationHistory("asset1", ["A", "B", "D"]))
        return eng

    def test_predicts_most_frequent_next(self):
        eng = self._engine_with_history()
        result = eng.predict_next("asset1", "B")
        assert result.predicted_next == "C"
        assert result.confidence == pytest.approx(5 / 6)

    def test_alternatives_listed(self):
        eng = self._engine_with_history()
        result = eng.predict_next("asset1", "B")
        assert "D" in result.alternatives

    def test_no_history_returns_none(self):
        eng = _build_linear_graph()
        result = eng.predict_next("asset1", "A")
        assert result.predicted_next is None
        assert result.confidence == 0.0

    def test_record_history_updates_stats(self):
        eng = _build_linear_graph()
        eng.record_history(LocationHistory("a1", ["A", "B", "C"]))
        stats = eng.get_stats()
        assert stats["nodes_with_history"] == 2  # A and B have outgoing transitions

    def test_route_to_dict_has_route_id(self):
        eng = _build_linear_graph()
        route = eng.find_optimal_route("A", "D")
        d = route.to_dict()
        assert "route_id" in d
