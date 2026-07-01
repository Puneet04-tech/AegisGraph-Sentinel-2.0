"""Geofencing data models for asset boundary monitoring."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4


@dataclass
class GeoPoint:
    """A geographic coordinate."""

    lat: float
    lon: float

    def __post_init__(self) -> None:
        if not (-90.0 <= self.lat <= 90.0):
            raise ValueError(f"Latitude {self.lat} out of range [-90, 90]")
        if not (-180.0 <= self.lon <= 180.0):
            raise ValueError(f"Longitude {self.lon} out of range [-180, 180]")


@dataclass
class Geofence:
    """A named polygon boundary with optional metadata."""

    name: str
    boundary: List[GeoPoint]
    fence_id: str = field(default_factory=lambda: str(uuid4()))
    description: str = ""
    alert_on_exit: bool = True
    alert_on_entry: bool = False

    def __post_init__(self) -> None:
        if len(self.boundary) < 3:
            raise ValueError("A geofence boundary must have at least 3 points.")


@dataclass
class AssetLocation:
    """A point-in-time location reading for a tracked asset."""

    asset_id: str
    position: GeoPoint
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class GeofenceEvent:
    """Recorded entry or exit event for an asset crossing a geofence boundary."""

    event_id: str = field(default_factory=lambda: str(uuid4()))
    asset_id: str = ""
    fence_id: str = ""
    fence_name: str = ""
    event_type: str = ""  # "entry" | "exit"
    position: Optional[GeoPoint] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "asset_id": self.asset_id,
            "fence_id": self.fence_id,
            "fence_name": self.fence_name,
            "event_type": self.event_type,
            "lat": self.position.lat if self.position else None,
            "lon": self.position.lon if self.position else None,
            "timestamp": self.timestamp.isoformat(),
        }
