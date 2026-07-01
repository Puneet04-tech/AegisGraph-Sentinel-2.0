"""Tests for the geofencing engine and models."""

import pytest

from src.geofencing import AssetLocation, GeoPoint, Geofence, GeofencingEngine, GeofenceEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _square_fence(name: str = "test-zone", cx: float = 0.0, cy: float = 0.0, half: float = 1.0) -> Geofence:
    """Return an axis-aligned square geofence centred at (cx, cy)."""
    return Geofence(
        name=name,
        boundary=[
            GeoPoint(cy - half, cx - half),
            GeoPoint(cy + half, cx - half),
            GeoPoint(cy + half, cx + half),
            GeoPoint(cy - half, cx + half),
        ],
        alert_on_exit=True,
        alert_on_entry=True,
    )


def _loc(asset_id: str, lat: float, lon: float) -> AssetLocation:
    return AssetLocation(asset_id=asset_id, position=GeoPoint(lat, lon))


# ---------------------------------------------------------------------------
# Model validation
# ---------------------------------------------------------------------------

class TestGeoPoint:
    def test_valid_coordinates(self):
        p = GeoPoint(37.7749, -122.4194)
        assert p.lat == 37.7749

    def test_invalid_latitude(self):
        with pytest.raises(ValueError):
            GeoPoint(91.0, 0.0)

    def test_invalid_longitude(self):
        with pytest.raises(ValueError):
            GeoPoint(0.0, 181.0)


class TestGeofence:
    def test_too_few_points_raises(self):
        with pytest.raises(ValueError):
            Geofence(name="bad", boundary=[GeoPoint(0, 0), GeoPoint(1, 1)])

    def test_valid_fence_created(self):
        fence = _square_fence()
        assert fence.fence_id != ""
        assert len(fence.boundary) == 4


# ---------------------------------------------------------------------------
# Engine: fence management
# ---------------------------------------------------------------------------

class TestGeofencingEngineManagement:
    def test_add_and_list(self):
        engine = GeofencingEngine()
        fence = _square_fence("zone-a")
        engine.add_geofence(fence)
        listing = engine.list_geofences()
        assert len(listing) == 1
        assert listing[0]["name"] == "zone-a"

    def test_remove_fence(self):
        engine = GeofencingEngine()
        fid = engine.add_geofence(_square_fence())
        assert engine.remove_geofence(fid) is True
        assert engine.list_geofences() == []

    def test_remove_nonexistent_returns_false(self):
        engine = GeofencingEngine()
        assert engine.remove_geofence("no-such-id") is False


# ---------------------------------------------------------------------------
# Engine: breach detection
# ---------------------------------------------------------------------------

class TestGeofencingEngineDetection:
    def setup_method(self):
        self.engine = GeofencingEngine()
        self.fence = _square_fence(cx=0.0, cy=0.0, half=1.0)
        self.fid = self.engine.add_geofence(self.fence)

    def test_first_update_inside_no_event(self):
        events = self.engine.update_asset_location(_loc("a1", 0.0, 0.0))
        assert events == []

    def test_exit_triggers_event(self):
        self.engine.update_asset_location(_loc("a1", 0.0, 0.0))  # inside
        events = self.engine.update_asset_location(_loc("a1", 5.0, 5.0))  # outside
        assert len(events) == 1
        assert events[0].event_type == "exit"
        assert events[0].asset_id == "a1"
        assert events[0].fence_name == self.fence.name

    def test_entry_triggers_event(self):
        self.engine.update_asset_location(_loc("a1", 5.0, 5.0))  # outside
        events = self.engine.update_asset_location(_loc("a1", 0.0, 0.0))  # inside
        assert len(events) == 1
        assert events[0].event_type == "entry"

    def test_no_event_when_staying_inside(self):
        self.engine.update_asset_location(_loc("a1", 0.0, 0.0))
        events = self.engine.update_asset_location(_loc("a1", 0.5, 0.5))
        assert events == []

    def test_no_event_when_staying_outside(self):
        self.engine.update_asset_location(_loc("a1", 5.0, 5.0))
        events = self.engine.update_asset_location(_loc("a1", 6.0, 6.0))
        assert events == []

    def test_alert_callback_called(self):
        fired = []
        engine = GeofencingEngine(alert_callback=fired.append)
        fid = engine.add_geofence(_square_fence())
        engine.update_asset_location(_loc("a2", 0.0, 0.0))
        engine.update_asset_location(_loc("a2", 5.0, 5.0))
        assert len(fired) == 1
        assert fired[0].event_type == "exit"

    def test_is_inside(self):
        self.engine.update_asset_location(_loc("a1", 0.0, 0.0))
        assert self.engine.is_inside("a1", self.fid) is True

    def test_is_inside_unknown_returns_none(self):
        assert self.engine.is_inside("unknown", self.fid) is None


# ---------------------------------------------------------------------------
# Engine: event history queries
# ---------------------------------------------------------------------------

class TestGeofencingEngineQueries:
    def test_get_events_filtered_by_asset(self):
        engine = GeofencingEngine()
        fid = engine.add_geofence(_square_fence())

        engine.update_asset_location(_loc("a1", 0.0, 0.0))
        engine.update_asset_location(_loc("a1", 5.0, 5.0))
        engine.update_asset_location(_loc("a2", 0.0, 0.0))
        engine.update_asset_location(_loc("a2", 5.0, 5.0))

        a1_events = engine.get_events(asset_id="a1")
        assert all(e.asset_id == "a1" for e in a1_events)

    def test_get_events_filtered_by_type(self):
        engine = GeofencingEngine()
        engine.add_geofence(_square_fence())
        engine.update_asset_location(_loc("a1", 0.0, 0.0))
        engine.update_asset_location(_loc("a1", 5.0, 5.0))
        engine.update_asset_location(_loc("a1", 0.0, 0.0))

        exits = engine.get_events(event_type="exit")
        entries = engine.get_events(event_type="entry")
        assert len(exits) == 1
        assert len(entries) == 1

    def test_event_to_dict(self):
        engine = GeofencingEngine()
        engine.add_geofence(_square_fence())
        engine.update_asset_location(_loc("a1", 0.0, 0.0))
        engine.update_asset_location(_loc("a1", 5.0, 5.0))
        events = engine.get_events(event_type="exit")
        d = events[0].to_dict()
        assert d["event_type"] == "exit"
        assert "timestamp" in d

    def test_get_stats(self):
        engine = GeofencingEngine()
        engine.add_geofence(_square_fence())
        engine.update_asset_location(_loc("a1", 0.0, 0.0))
        engine.update_asset_location(_loc("a1", 5.0, 5.0))
        stats = engine.get_stats()
        assert stats["total_fences"] == 1
        assert stats["tracked_assets"] == 1
        assert stats["total_events"] == 1
