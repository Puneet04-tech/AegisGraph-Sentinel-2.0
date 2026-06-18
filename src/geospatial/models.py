"""
Models for Issue #1023 - Geofencing.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class LocationUpdate(BaseModel):
    """Represents a location update with encrypted coordinates."""
    update_id: str
    asset_id: str
    encrypted_latitude: bytes
    encrypted_longitude: bytes
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    accuracy: float = 1.0


class Asset(BaseModel):
    """Represents an asset with encrypted coordinates."""
    asset_id: str
    name: str
    encrypted_last_lat: Optional[bytes] = None
    encrypted_last_lon: Optional[bytes] = None
    last_updated: Optional[datetime] = None
    accuracy: float = 1.0


class Geofence(BaseModel):
    """Represents a geofence boundary."""
    geofence_id: str
    name: str
    boundary_type: str = "circle"  # "circle" or "polygon"
    encrypted_center_lat: Optional[bytes] = None
    encrypted_center_lon: Optional[bytes] = None
    radius_meters: Optional[float] = None
    encrypted_coordinates: Optional[bytes] = None
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
