"""
Tests for the Geospatial Asset Tracking Suite.
"""

import asyncio
import json
import zlib
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from fastapi import WebSocket

from src.geospatial.models import Geofence, GeofenceBreach, Route
from src.geospatial.service import (
    GeospatialCryptor,
    AccessAuditLogger,
    KalmanTracker,
    GeospatialTrackingService,
    RouteOptimizationEngine,
)
from src.api.geospatial_routes import tracking_service, routing_engine


def test_coordinate_encryption():
    """Verify issue #1021: Geospatial data encrypted at rest and tenant isolation."""
    cryptor = GeospatialCryptor()
    tenant_a = "tenant_a"
    tenant_b = "tenant_b"
    
    key_a = cryptor.get_tenant_key(tenant_a)
    key_b = cryptor.get_tenant_key(tenant_b)

    assert key_a != key_b
    assert len(key_a) == 32

    lat = 19.0760
    lon = 72.8777

    # Encrypt
    enc_lat_a = cryptor.encrypt_coordinate(lat, key_a)
    enc_lon_a = cryptor.encrypt_coordinate(lon, key_a)

    assert enc_lat_a != lat
    assert enc_lon_a != lon

    # Decrypt
    dec_lat_a = cryptor.decrypt_coordinate(enc_lat_a, key_a)
    dec_lon_a = cryptor.decrypt_coordinate(enc_lon_a, key_a)

    assert pytest.approx(dec_lat_a, rel=1e-5) == lat
    assert pytest.approx(dec_lon_a, rel=1e-5) == lon

    # Verify tenant isolation (decrypt with wrong tenant key should fail)
    with pytest.raises(Exception):
        cryptor.decrypt_coordinate(enc_lat_a, key_b)


def test_access_audit_logging(caplog):
    """Verify issue #1021: GDPR access auditing."""
    import logging
    # Temporarily set log level of geospatial logger to INFO
    logger = logging.getLogger("geospatial")
    logger.setLevel(logging.INFO)

    AccessAuditLogger.log_access("analyst_test", "view_asset", "asset_123", "tenant_a")
    
    assert any("GDPR Location Access" in record.message for record in caplog.records)
    assert any("analyst_test" in record.message for record in caplog.records)
    assert any("asset_123" in record.message for record in caplog.records)


@pytest.mark.asyncio
async def test_realtime_queue_processing():
    """Verify issue #1022: Async queue and batch processing of updates."""
    cryptor = GeospatialCryptor()
    audit_logger = AccessAuditLogger()
    service = GeospatialTrackingService(cryptor, audit_logger)
    
    # Start batch processing
    service.start_batch_processing()
    assert service.batch_processing_active

    try:
        # Enqueue 5 updates
        for i in range(5):
            await service.add_update_to_queue("asset_batch", 19.0760 + i*0.01, 72.8777, 1.0, 1.0)

        # Allow some time for batch processing task to consume updates
        await asyncio.sleep(0.3)
        
        # Verify updates processed
        assert service.update_queue.empty()
        assert "asset_batch" in service.assets
    finally:
        await service.stop_batch_processing()


@pytest.mark.asyncio
async def test_delta_update_filtering():
    """Verify issue #1022: Delta update filtering to minimize redundant pushes."""
    cryptor = GeospatialCryptor()
    audit_logger = AccessAuditLogger()
    service = GeospatialTrackingService(cryptor, audit_logger)
    
    # Setup mock websocket listener
    ws_mock = AsyncMock()
    service.websocket_listeners.add(ws_mock)

    # First update (always pushed)
    await service._process_location_update("asset_delta", 19.0760, 72.8777, 1.0, 1.0)
    assert ws_mock.send_bytes.call_count == 1
    
    # Second update very close (0.5 meters change) - should be filtered
    await service._process_location_update("asset_delta", 19.076001, 72.877701, 1.0, 1.0)
    assert ws_mock.send_bytes.call_count == 1  # call count remains 1

    # Third update far away (10 meters change) - should be pushed
    await service._process_location_update("asset_delta", 19.0761, 72.8777, 1.0, 1.0)
    assert ws_mock.send_bytes.call_count == 2  # call count increased


@pytest.mark.asyncio
async def test_compressed_websocket_broadcast():
    """Verify issue #1022: WebSocket payload compression with zlib."""
    cryptor = GeospatialCryptor()
    audit_logger = AccessAuditLogger()
    service = GeospatialTrackingService(cryptor, audit_logger)
    
    ws_mock = AsyncMock()
    service.websocket_listeners.add(ws_mock)

    # Trigger update
    await service._process_location_update("asset_compress", 19.0760, 72.8777, 1.0, 1.0)

    assert ws_mock.send_bytes.call_count == 1
    
    # Verify sent bytes can be decompressed back to the expected json
    sent_bytes = ws_mock.send_bytes.call_args[0][0]
    decompressed_str = zlib.decompress(sent_bytes).decode("utf-8")
    payload = json.loads(decompressed_str)

    assert payload["type"] == "LOCATION_UPDATE"
    assert payload["asset_id"] == "asset_compress"
    assert payload["latitude"] == 19.0760


@pytest.mark.asyncio
async def test_geofencing_breach_and_webhooks():
    """Verify issue #1023: Circular & polygonal geofences, transition alerts, and webhooks."""
    cryptor = GeospatialCryptor()
    audit_logger = AccessAuditLogger()
    service = GeospatialTrackingService(cryptor, audit_logger)
    
    tenant_key = cryptor.get_tenant_key("default_tenant")

    # 1. Circle Geofence: center Mumbai, radius 100 meters
    circle_fence = Geofence(
        geofence_id="fence_c",
        name="Mumbai Office",
        boundary_type="circle",
        encrypted_center_lat=cryptor.encrypt_coordinate(19.0760, tenant_key),
        encrypted_center_lon=cryptor.encrypt_coordinate(72.8777, tenant_key),
        radius_meters=100.0,
        tenant_id="default_tenant"
    )
    service.register_geofence(circle_fence)

    # Register mock webhook URL
    service.register_webhook("http://example.com/webhook")

    # Mock post call
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        # First location: inside geofence (no breach event triggered, just state initialization)
        await service._process_location_update("asset_f", 19.0760, 72.8777, 1.0, 1.0)
        assert len(service.breach_history) == 0
        mock_post.assert_not_called()

        # Second location: outside geofence (EXIT breach event triggered)
        await service._process_location_update("asset_f", 19.0860, 72.8777, 1.0, 1.0)
        assert len(service.breach_history) == 1
        assert service.breach_history[0].breach_type == "EXIT"
        mock_post.assert_called_once()

        # Third location: back inside geofence (ENTER breach event triggered)
        await service._process_location_update("asset_f", 19.0760, 72.8777, 1.0, 1.0)
        assert len(service.breach_history) == 2
        assert service.breach_history[1].breach_type == "ENTER"


def test_kalman_filter_drift_correction():
    """Verify issue #1024: Sensor drift correction via Kalman Filtering."""
    # Initialize tracker with initial coordinate
    tracker = KalmanTracker(19.0760, 72.8777)
    
    # Update with some noisy data points
    tracker.update(19.0762, 72.8779, 10.0, 0.5)  # noisy update
    tracker.update(19.0761, 72.8778, 2.0, 1.0)   # accurate update
    
    lat, lon = tracker.get_position()
    
    # Coordinates should be smoothed/filtered and closer to the accurate observation
    assert abs(lat - 19.0761) < 0.001
    assert abs(lon - 72.8778) < 0.001


def test_route_optimization_and_prediction():
    """Verify issue #1025: A* pathfinding, deviation detection, and path prediction."""
    engine = RouteOptimizationEngine()

    # 1. Optimize route on 2D grid graph
    route = engine.optimize_route("asset_route", source=(0, 0), target=(3, 4))
    
    assert len(route.points) > 0
    assert route.points[0] == engine.node_positions[(0, 0)]
    assert route.points[-1] == engine.node_positions[(3, 4)]
    assert route.eta_minutes > 0.0

    # 2. Path prediction based on Kalman Tracker velocity vector
    tracker = KalmanTracker(19.0760, 72.8777)
    # Simulate movement velocity in north-east direction
    tracker.x[2] = 0.0001  # lat velocity
    tracker.x[3] = 0.0002  # lon velocity
    
    pred_lat, pred_lon = engine.predict_next_location(tracker, dt=10.0)
    assert pred_lat == 19.0760 + 0.0001 * 10.0
    assert pred_lon == 72.8777 + 0.0002 * 10.0

    # 3. Route Deviation Detection
    # If asset is right on the route
    assert not engine.detect_route_deviation(route.points[0][0], route.points[0][1], route, threshold_meters=50.0)
    
    # If asset is far away from the route (e.g. 5km away)
    assert engine.detect_route_deviation(19.5, 73.5, route, threshold_meters=50.0)


def test_api_endpoints_integration(api_client):
    """Integrations test using FastAPI TestClient to test all REST endpoints."""
    # Reset tracking service datasets
    tracking_service.assets.clear()
    tracking_service.geofences.clear()
    tracking_service.breach_history.clear()

    # 1. Submit location update
    response = api_client.post("/api/v1/geospatial/update", json={
        "asset_id": "asset_api",
        "latitude": 19.0760,
        "longitude": 72.8777,
        "accuracy": 1.0,
        "signal_strength": 1.0
    })
    assert response.status_code == 200
    assert response.json()["status"] == "queued"

    # 2. Create circular geofence
    response = api_client.post("/api/v1/geospatial/geofences", json={
        "geofence_id": "fence_api",
        "name": "Mumbai HQ",
        "boundary_type": "circle",
        "center_lat": 19.0760,
        "center_lon": 72.8777,
        "radius_meters": 150.0,
        "tenant_id": "default_tenant"
    })
    assert response.status_code == 200
    assert response.json()["status"] == "created"

    # 3. List geofences
    response = api_client.get("/api/v1/geospatial/geofences")
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["geofence_id"] == "fence_api"

    # 4. List breaches (should be empty initially)
    response = api_client.get("/api/v1/geospatial/breaches")
    assert response.status_code == 200
    assert len(response.json()) == 0

    # 5. Optimize route
    response = api_client.post("/api/v1/geospatial/routes/optimize", json={
        "asset_id": "asset_api",
        "source_x": 0,
        "source_y": 0,
        "target_x": 2,
        "target_y": 3
    })
    assert response.status_code == 200
    assert len(response.json()["points"]) > 0
    assert "eta_minutes" in response.json()
