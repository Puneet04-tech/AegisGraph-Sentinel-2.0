"""
Tests for Issue #1024 - Drift Correction and Kalman Filtering.
"""

import asyncio
import json
import logging
import zlib
import pytest
from unittest.mock import AsyncMock, patch
from src.geospatial.service import GeospatialCryptor, AccessAuditLogger, GeospatialTrackingService, KalmanTracker
from src.geospatial.models import Geofence, GeofenceBreach
from src.api.geospatial_routes import tracking_service


def test_coordinate_encryption():
    cryptor = GeospatialCryptor()
    tenant_key = cryptor.get_tenant_key("default_tenant")
    enc_lat = cryptor.encrypt_coordinate(19.0760, tenant_key)
    assert pytest.approx(cryptor.decrypt_coordinate(enc_lat, tenant_key), rel=1e-5) == 19.0760


def test_access_audit_logging(caplog):
    logger = logging.getLogger("geospatial")
    logger.setLevel(logging.INFO)
    AccessAuditLogger.log_access("user", "read", "asset", "tenant")
    assert any("GDPR Location Access" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_realtime_queue_processing():
    cryptor = GeospatialCryptor()
    audit_logger = AccessAuditLogger()
    service = GeospatialTrackingService(cryptor, audit_logger)
    service.start_batch_processing()
    try:
        await service.add_update_to_queue("asset_batch", 19.0760, 72.8777, 1.0)
        await asyncio.sleep(0.1)
        assert service.update_queue.empty()
    finally:
        await service.stop_batch_processing()


@pytest.mark.asyncio
async def test_delta_update_filtering():
    cryptor = GeospatialCryptor()
    audit_logger = AccessAuditLogger()
    service = GeospatialTrackingService(cryptor, audit_logger)
    ws_mock = AsyncMock()
    service.websocket_listeners.add(ws_mock)

    await service._process_location_update("asset_delta", 19.0760, 72.8777, 1.0, 1.0)
    assert ws_mock.send_bytes.call_count == 1


@pytest.mark.asyncio
async def test_geofencing_breach_and_webhooks():
    cryptor = GeospatialCryptor()
    audit_logger = AccessAuditLogger()
    service = GeospatialTrackingService(cryptor, audit_logger)
    tenant_key = cryptor.get_tenant_key("default_tenant")

    circle_fence = Geofence(
        geofence_id="fence_c",
        name="Office",
        boundary_type="circle",
        encrypted_center_lat=cryptor.encrypt_coordinate(19.0760, tenant_key),
        encrypted_center_lon=cryptor.encrypt_coordinate(72.8777, tenant_key),
        radius_meters=100.0,
        tenant_id="default_tenant"
    )
    service.register_geofence(circle_fence)
    service.register_webhook("http://example.com/webhook")

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        await service._process_location_update("asset_f", 19.0760, 72.8777, 1.0, 1.0)
        assert len(service.breach_history) == 0
        await service._process_location_update("asset_f", 19.0860, 72.8777, 1.0, 1.0)
        assert len(service.breach_history) == 1
        mock_post.assert_called_once()


def test_kalman_filter_drift_correction():
    """Verify state estimation filtering works as expected for noisy points."""
    tracker = KalmanTracker(19.0760, 72.8777)
    
    # Update with some noisy data points
    tracker.update(19.0762, 72.8779, 10.0, 0.5)
    tracker.update(19.0761, 72.8778, 2.0, 1.0)
    
    lat, lon = tracker.get_position()
    
    assert abs(lat - 19.0761) < 0.001
    assert abs(lon - 72.8778) < 0.001


def test_api_endpoints_integration(api_client):
    tracking_service.assets.clear()
    tracking_service.geofences.clear()

    response = api_client.post("/api/v1/geospatial/update", json={
        "asset_id": "asset_api",
        "latitude": 19.0760,
        "longitude": 72.8777,
        "accuracy": 1.0,
        "signal_strength": 1.0
    })
    assert response.status_code == 200


def test_route_optimization_and_prediction(api_client):
    tracking_service.assets.clear()
    tracking_service.geofences.clear()

    # Test route optimization
    response = api_client.post("/api/v1/geospatial/routes/optimize", json={
        "asset_id": "asset_route",
        "source": [0, 0],
        "target": [2, 2]
    })
    assert response.status_code == 200
    data = response.json()
    assert data["asset_id"] == "asset_route"
    assert "points" in data
    assert len(data["points"]) > 0
    assert data["eta_minutes"] > 0

    # Test prediction
    from src.geospatial.service import KalmanTracker
    tracking_service.active_trackers["asset_predict"] = KalmanTracker(19.0760, 72.8777)

    response_pred = api_client.get("/api/v1/geospatial/assets/asset_predict/predict?dt=15.0")
    assert response_pred.status_code == 200
    pred_data = response_pred.json()
    assert pred_data["asset_id"] == "asset_predict"
    assert "predicted_latitude" in pred_data
    assert "predicted_longitude" in pred_data
    assert pred_data["dt"] == 15.0

    # Test prediction for non-existent asset
    response_missing = api_client.get("/api/v1/geospatial/assets/non_existent_asset/predict")
    assert response_missing.status_code == 404
