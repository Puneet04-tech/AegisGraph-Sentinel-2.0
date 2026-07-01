"""Geofencing module: boundary definition, breach detection, and event alerts."""

from .engine import GeofencingEngine
from .models import AssetLocation, GeoPoint, Geofence, GeofenceEvent

__all__ = [
    "GeofencingEngine",
    "Geofence",
    "GeoPoint",
    "AssetLocation",
    "GeofenceEvent",
]
