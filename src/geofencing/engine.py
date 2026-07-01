"""Geofencing engine: boundary detection, breach alerts, and event history."""

from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from .models import AssetLocation, GeoPoint, Geofence, GeofenceEvent


def _point_in_polygon(point: GeoPoint, polygon: List[GeoPoint]) -> bool:
    """Ray-casting algorithm to test whether *point* lies inside *polygon*."""
    x, y = point.lon, point.lat
    inside = False
    n = len(polygon)
    j = n - 1
    for i in range(n):
        xi, yi = polygon[i].lon, polygon[i].lat
        xj, yj = polygon[j].lon, polygon[j].lat
        if ((yi > y) != (yj > y)) and (x < (xj - xi) * (y - yi) / (yj - yi) + xi):
            inside = not inside
        j = i
    return inside


class GeofencingEngine:
    """
    Manages a registry of geofences and tracks the last-known position of each
    asset so it can emit entry/exit events whenever an asset crosses a boundary.
    """

    def __init__(self, alert_callback: Optional[Callable[[GeofenceEvent], None]] = None) -> None:
        self._fences: Dict[str, Geofence] = {}
        self._asset_inside: Dict[str, Dict[str, bool]] = {}  # asset_id -> fence_id -> inside
        self._events: List[GeofenceEvent] = []
        self._alert_callback = alert_callback

    # ------------------------------------------------------------------
    # Fence management
    # ------------------------------------------------------------------

    def add_geofence(self, fence: Geofence) -> str:
        self._fences[fence.fence_id] = fence
        return fence.fence_id

    def remove_geofence(self, fence_id: str) -> bool:
        if fence_id in self._fences:
            del self._fences[fence_id]
            for state in self._asset_inside.values():
                state.pop(fence_id, None)
            return True
        return False

    def list_geofences(self) -> List[dict]:
        return [
            {
                "fence_id": f.fence_id,
                "name": f.name,
                "description": f.description,
                "boundary_points": len(f.boundary),
            }
            for f in self._fences.values()
        ]

    # ------------------------------------------------------------------
    # Asset position updates
    # ------------------------------------------------------------------

    def update_asset_location(self, location: AssetLocation) -> List[GeofenceEvent]:
        """
        Record a new position for *location.asset_id* and return any boundary
        events that were triggered (entry or exit for each registered geofence).
        """
        aid = location.asset_id
        new_events: List[GeofenceEvent] = []

        for fence_id, fence in self._fences.items():
            was_inside = self._asset_inside.get(aid, {}).get(fence_id)
            now_inside = _point_in_polygon(location.position, fence.boundary)

            if was_inside is None:
                # First observation for this (asset, fence) pair — initialise state.
                self._asset_inside.setdefault(aid, {})[fence_id] = now_inside
                continue

            if now_inside == was_inside:
                self._asset_inside.setdefault(aid, {})[fence_id] = now_inside
                continue

            # State changed: determine event type and check alert flags.
            event_type = "entry" if now_inside else "exit"
            should_alert = (event_type == "exit" and fence.alert_on_exit) or (
                event_type == "entry" and fence.alert_on_entry
            )

            if should_alert:
                event = GeofenceEvent(
                    asset_id=aid,
                    fence_id=fence_id,
                    fence_name=fence.name,
                    event_type=event_type,
                    position=location.position,
                    timestamp=location.timestamp,
                )
                self._events.append(event)
                new_events.append(event)
                if self._alert_callback:
                    self._alert_callback(event)

            self._asset_inside.setdefault(aid, {})[fence_id] = now_inside

        return new_events

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def is_inside(self, asset_id: str, fence_id: str) -> Optional[bool]:
        return self._asset_inside.get(asset_id, {}).get(fence_id)

    def get_events(
        self,
        asset_id: Optional[str] = None,
        fence_id: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[GeofenceEvent]:
        events = self._events
        if asset_id:
            events = [e for e in events if e.asset_id == asset_id]
        if fence_id:
            events = [e for e in events if e.fence_id == fence_id]
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events

    def get_stats(self) -> dict:
        return {
            "total_fences": len(self._fences),
            "tracked_assets": len(self._asset_inside),
            "total_events": len(self._events),
        }
