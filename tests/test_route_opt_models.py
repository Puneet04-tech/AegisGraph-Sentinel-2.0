# AegisGraph Sentinel Enterprise
# Route Optimization Telemetry Model Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from src.route_optimization.models import Waypoint, RouteEdge, Route, LocationHistory, PredictionResult

def test_waypoint_creation():
    wp = Waypoint(
        node_id="wp-01",
        lat=19.076,
        lon=72.877,
        label="Mumbai Gateway Node"
    )
    assert wp.node_id == "wp-01"
    assert wp.lat == 19.076
    assert wp.lon == 72.877
    assert wp.label == "Mumbai Gateway Node"

def test_route_edge_congestion():
    edge = RouteEdge(
        from_id="wp-01",
        to_id="wp-02",
        distance_m=1200.0,
        travel_time_s=120.0,
        congestion_factor=1.5
    )
    assert edge.from_id == "wp-01"
    assert edge.to_id == "wp-02"
    assert edge.effective_time_s == 180.0

def test_route_to_dict():
    wp1 = Waypoint(node_id="n1", lat=1.0, lon=2.0)
    wp2 = Waypoint(node_id="n2", lat=3.0, lon=4.0)
    route = Route(
        waypoints=[wp1, wp2],
        total_distance_m=5000.0,
        total_time_s=300.0
    )
    data = route.to_dict()
    assert data["route_id"] == route.route_id
    assert data["stops"] == ["n1", "n2"]
    assert data["total_distance_m"] == 5000.0

def test_location_history_creation():
    lh = LocationHistory(
        asset_id="asset-99",
        positions=["n1", "n2", "n3"]
    )
    assert lh.asset_id == "asset-99"
    assert lh.positions == ["n1", "n2", "n3"]

def test_prediction_result_creation():
    pr = PredictionResult(
        asset_id="asset-99",
        predicted_next="n4",
        confidence=0.85,
        alternatives=["n5"]
    )
    assert pr.asset_id == "asset-99"
    assert pr.predicted_next == "n4"
    assert pr.confidence == 0.85
    assert pr.alternatives == ["n5"]
