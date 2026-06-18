"""
Models for Issue #1021 - Geospatial Encryption.
"""

from datetime import datetime
from typing import Optional
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
