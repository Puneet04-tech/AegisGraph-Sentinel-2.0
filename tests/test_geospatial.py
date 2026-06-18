"""
Tests for Issue #1022 - Real-Time Update Pipeline.
"""

import asyncio
import json
import logging
import zlib
import pytest
from unittest.mock import AsyncMock
from src.geospatial.service import GeospatialCryptor, AccessAuditLogger, GeospatialTrackingService
from fastapi.testclient import TestClient
from src.api.geospatial_routes import tracking_service


def test_coordinate_encryption():
    """Verify coordinate encryption."""
    cryptor = GeospatialCryptor()
    tenant_key = cryptor.get_tenant_key("default_tenant")
    enc_lat = cryptor.encrypt_coordinate(19.0760, tenant_key)
    dec_lat = cryptor.decrypt_coordinate(enc_lat, tenant_key)
    assert pytest.approx(dec_lat, rel=1e-5) == 19.0760


def test_access_audit_logging(caplog):
    """Verify access logging."""
    logger = logging.getLogger("geospatial")
    logger.setLevel(logging.INFO)
    AccessAuditLogger.log_access("user", "read", "asset", "tenant")
    assert any("GDPR Location Access" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_realtime_queue_processing():
    """Verify non-blocking queue and asynchronous batch processing."""
    cryptor = GeospatialCryptor()
    audit_logger = AccessAuditLogger()
    service = GeospatialTrackingService(cryptor, audit_logger)
    
    service.start_batch_processing()
    try:
        await service.add_update_to_queue("asset_batch", 19.0760, 72.8777, 1.0)
        await asyncio.sleep(0.1)
        assert service.update_queue.empty()
        assert "asset_batch" in service.assets
    finally:
        await service.stop_batch_processing()


@pytest.mark.asyncio
async def test_delta_update_filtering():
    """Verify delta filtering for small movements."""
    cryptor = GeospatialCryptor()
    audit_logger = AccessAuditLogger()
    service = GeospatialTrackingService(cryptor, audit_logger)
    ws_mock = AsyncMock()
    service.websocket_listeners.add(ws_mock)

    await service._process_location_update("asset_delta", 19.0760, 72.8777, 1.0)
    assert ws_mock.send_bytes.call_count == 1

    # Close movement (0.5 meters) - should be filtered
    await service._process_location_update("asset_delta", 19.076001, 72.877701, 1.0)
    assert ws_mock.send_bytes.call_count == 1


@pytest.mark.asyncio
async def test_compressed_websocket_broadcast():
    """Verify WebSocket compression with zlib."""
    cryptor = GeospatialCryptor()
    audit_logger = AccessAuditLogger()
    service = GeospatialTrackingService(cryptor, audit_logger)
    ws_mock = AsyncMock()
    service.websocket_listeners.add(ws_mock)

    await service._process_location_update("asset_compress", 19.0760, 72.8777, 1.0)
    assert ws_mock.send_bytes.call_count == 1

    sent_bytes = ws_mock.send_bytes.call_args[0][0]
    payload = json.loads(zlib.decompress(sent_bytes).decode("utf-8"))
    assert payload["asset_id"] == "asset_compress"


def test_api_endpoints_integration(api_client):
    """Verify REST API and WebSocket integration path."""
    tracking_service.assets.clear()

    response = api_client.post("/api/v1/geospatial/update", json={
        "asset_id": "asset_api",
        "latitude": 19.0760,
        "longitude": 72.8777,
        "accuracy": 1.0
    })
    assert response.status_code == 200
    assert response.json()["status"] == "queued"
