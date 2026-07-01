"""Data models for route optimization and path prediction."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4


@dataclass
class Waypoint:
    """A named geographic stop on a route."""

    node_id: str
    lat: float
    lon: float
    label: str = ""


@dataclass
class RouteEdge:
    """A directed connection between two waypoints with an associated cost."""

    from_id: str
    to_id: str
    distance_m: float
    travel_time_s: float = 0.0
    congestion_factor: float = 1.0  # >1 means slower than normal

    @property
    def effective_time_s(self) -> float:
        return self.travel_time_s * self.congestion_factor


@dataclass
class Route:
    """An ordered sequence of waypoints forming a complete path."""

    route_id: str = field(default_factory=lambda: str(uuid4()))
    waypoints: List[Waypoint] = field(default_factory=list)
    total_distance_m: float = 0.0
    total_time_s: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "route_id": self.route_id,
            "stops": [w.node_id for w in self.waypoints],
            "total_distance_m": self.total_distance_m,
            "total_time_s": self.total_time_s,
        }


@dataclass
class LocationHistory:
    """Historical sequence of positions for a tracked asset."""

    asset_id: str
    positions: List[str] = field(default_factory=list)  # ordered list of node_ids


@dataclass
class PredictionResult:
    """Result of a next-location prediction."""

    asset_id: str
    predicted_next: Optional[str]
    confidence: float  # 0.0 – 1.0
    alternatives: List[str] = field(default_factory=list)
