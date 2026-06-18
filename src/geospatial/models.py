"""
Models for the Geospatial Asset Tracking Suite.
"""

from datetime import datetime
from typing import List, Tuple, Optional, Dict, Any
from pydantic import BaseModel, Field


class LocationUpdate(BaseModel):
    """Represents a raw or encrypted location update."""
    update_id: str
    asset_id: str
    encrypted_latitude: bytes
    encrypted_longitude: bytes
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    accuracy: float = 1.0  # in meters
    signal_strength: float = 1.0  # e.g., SNR or satellite count scale


class Asset(BaseModel):
    """Represents an asset being tracked."""
    asset_id: str
    name: str
    encrypted_last_lat: Optional[bytes] = None
    encrypted_last_lon: Optional[bytes] = None
    last_updated: Optional[datetime] = None
    accuracy: float = 1.0
    calibration_bias_lat: float = 0.0
    calibration_bias_lon: float = 0.0


class Geofence(BaseModel):
    """Represents a geofence boundary."""
    geofence_id: str
    name: str
    boundary_type: str = "circle"  # "circle" or "polygon"
    encrypted_center_lat: Optional[bytes] = None  # for circle
    encrypted_center_lon: Optional[bytes] = None  # for circle
    radius_meters: Optional[float] = None          # for circle
    encrypted_coordinates: Optional[bytes] = None   # for polygon (JSON list of points, encrypted)
    tenant_id: str


class GeofenceBreach(BaseModel):
    """Represents a geofence breach event."""
    alert_id: str
    asset_id: str
    geofence_id: str
    breach_type: str  # "ENTER" or "EXIT"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    encrypted_lat: bytes
    encrypted_lon: bytes
    resolved: bool = False


class Route(BaseModel):
    """Represents a planned or optimized route."""
    route_id: str
    asset_id: str
    points: List[Tuple[float, float]] = Field(default_factory=list)  # list of (lat, lon)
    optimized_points: List[Tuple[float, float]] = Field(default_factory=list)
    eta_minutes: float = 0.0
    last_updated: datetime = Field(default_factory=datetime.utcnow)
