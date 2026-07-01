"""
Route optimisation and path prediction engine.

Uses Dijkstra's algorithm (via a min-heap) to find the shortest path between
any two nodes in a weighted directed graph, and a first-order Markov model
built from historical asset paths to predict the next likely location.
"""

import heapq
import math
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from .models import LocationHistory, PredictionResult, Route, RouteEdge, Waypoint

_INF = float("inf")


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6_371_000.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


class RouteOptimizationEngine:
    """
    Manages a graph of waypoints and edges, finds optimal routes, and predicts
    future asset locations from historical movement patterns.
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, Waypoint] = {}
        self._adj: Dict[str, List[RouteEdge]] = defaultdict(list)
        self._transitions: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def add_waypoint(self, waypoint: Waypoint) -> None:
        self._nodes[waypoint.node_id] = waypoint

    def add_edge(self, edge: RouteEdge) -> None:
        if edge.from_id not in self._nodes or edge.to_id not in self._nodes:
            raise ValueError(
                f"Both endpoints must be registered waypoints. "
                f"Missing: {[n for n in (edge.from_id, edge.to_id) if n not in self._nodes]}"
            )
        self._adj[edge.from_id].append(edge)

    # ------------------------------------------------------------------
    # Route optimisation (Dijkstra on effective travel time)
    # ------------------------------------------------------------------

    def find_optimal_route(self, origin_id: str, destination_id: str) -> Optional[Route]:
        """
        Return the time-optimal route from *origin_id* to *destination_id*,
        or None when no path exists.
        """
        if origin_id not in self._nodes or destination_id not in self._nodes:
            return None

        dist: Dict[str, float] = defaultdict(lambda: _INF)
        prev: Dict[str, Optional[str]] = {}
        dist[origin_id] = 0.0
        heap: List[Tuple[float, str]] = [(0.0, origin_id)]

        while heap:
            cost, node = heapq.heappop(heap)
            if cost > dist[node]:
                continue
            if node == destination_id:
                break
            for edge in self._adj.get(node, []):
                new_cost = dist[node] + edge.effective_time_s
                if new_cost < dist[edge.to_id]:
                    dist[edge.to_id] = new_cost
                    prev[edge.to_id] = node
                    heapq.heappush(heap, (new_cost, edge.to_id))

        if dist[destination_id] == _INF:
            return None

        # Reconstruct path
        path: List[str] = []
        cur: Optional[str] = destination_id
        while cur is not None:
            path.append(cur)
            cur = prev.get(cur)
        path.reverse()

        waypoints = [self._nodes[nid] for nid in path]

        # Compute total distance along reconstructed path
        total_dist = 0.0
        for i in range(len(path) - 1):
            a, b = self._nodes[path[i]], self._nodes[path[i + 1]]
            total_dist += _haversine_m(a.lat, a.lon, b.lat, b.lon)

        return Route(
            waypoints=waypoints,
            total_distance_m=total_dist,
            total_time_s=dist[destination_id],
        )

    # ------------------------------------------------------------------
    # Historical pattern learning
    # ------------------------------------------------------------------

    def record_history(self, history: LocationHistory) -> None:
        """
        Update the transition frequency table from an asset's movement history.
        Each consecutive (from, to) pair increments the transition count.
        """
        positions = history.positions
        for i in range(len(positions) - 1):
            self._transitions[positions[i]][positions[i + 1]] += 1

    # ------------------------------------------------------------------
    # Next-location prediction
    # ------------------------------------------------------------------

    def predict_next(self, asset_id: str, current_node_id: str) -> PredictionResult:
        """
        Predict the most likely next location for an asset currently at
        *current_node_id* using the learned first-order Markov model.
        """
        transitions = self._transitions.get(current_node_id, {})
        if not transitions:
            return PredictionResult(
                asset_id=asset_id,
                predicted_next=None,
                confidence=0.0,
            )

        total = sum(transitions.values())
        ranked = sorted(transitions.items(), key=lambda kv: kv[1], reverse=True)
        best_node, best_count = ranked[0]
        confidence = best_count / total
        alternatives = [nid for nid, _ in ranked[1:5]]

        return PredictionResult(
            asset_id=asset_id,
            predicted_next=best_node,
            confidence=confidence,
            alternatives=alternatives,
        )

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        return {
            "total_waypoints": len(self._nodes),
            "total_edges": sum(len(v) for v in self._adj.values()),
            "nodes_with_history": len(self._transitions),
        }
