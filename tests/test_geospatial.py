"""
Tests for Issue #1023 - Geofencing and Webhooks.
"""

import asyncio
import json
import logging
import zlib
import pytest
from unittest.mock import AsyncMock, patch
from src.geospatial.service import GeospatialCryptor, AccessAuditLogger, GeospatialTrackingService
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

    await service._process_location_update("asset_delta", 19.0760, 72.8777, 1.0)
    assert ws_mock.send_bytes.call_count == 1


@pytest.mark.asyncio
async def test_geofencing_breach_and_webhooks():
    """Verify circular geofence, state transitions, breach events, and webhook dispatches."""
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
        # Inside (init state)
        await service._process_location_update("asset_f", 19.0760, 72.8777, 1.0)
        assert len(service.breach_history) == 0
        mock_post.assert_not_called()

        # Outside (EXIT breach event)
        await service._process_location_update("asset_f", 19.0860, 72.8777, 1.0)
        assert len(service.breach_history) == 1
        assert service.breach_history[0].breach_type == "EXIT"
        mock_post.assert_called_once()


def test_api_endpoints_integration(api_client):
    tracking_service.assets.clear()
    tracking_service.geofences.clear()

    # Create circular geofence
    response = api_client.post("/api/v1/geospatial/geofences", json={
        "geofence_id": "fence_api",
        "name": "HQ",
        "boundary_type": "circle",
        "center_lat": 19.0760,
        "center_lon": 72.8777,
        "radius_meters": 150.0,
        "tenant_id": "default_tenant"
    })
    assert response.status_code == 200

    # List geofences
    response = api_client.get("/api/v1/geospatial/geofences")
    assert response.status_code == 200
    assert len(response.json()) == 1
