"""
Tests for Issue #1021 - Geospatial Encryption.
"""

import logging
import pytest
from src.geospatial.service import GeospatialCryptor, AccessAuditLogger
from fastapi.testclient import TestClient
from src.api.geospatial_routes import tracking_service


def test_coordinate_encryption():
    """Verify coordinate encryption at rest and tenant isolation."""
    cryptor = GeospatialCryptor()
    tenant_a = "tenant_a"
    tenant_b = "tenant_b"
    
    key_a = cryptor.get_tenant_key(tenant_a)
    key_b = cryptor.get_tenant_key(tenant_b)

    assert key_a != key_b

    lat = 19.0760
    lon = 72.8777

    enc_lat_a = cryptor.encrypt_coordinate(lat, key_a)
    enc_lon_a = cryptor.encrypt_coordinate(lon, key_a)

    assert enc_lat_a != lat
    assert enc_lon_a != lon

    dec_lat_a = cryptor.decrypt_coordinate(enc_lat_a, key_a)
    dec_lon_a = cryptor.decrypt_coordinate(enc_lon_a, key_a)

    assert pytest.approx(dec_lat_a, rel=1e-5) == lat
    assert pytest.approx(dec_lon_a, rel=1e-5) == lon

    with pytest.raises(Exception):
        cryptor.decrypt_coordinate(enc_lat_a, key_b)


def test_access_audit_logging(caplog):
    """Verify GDPR access auditing."""
    logger = logging.getLogger("geospatial")
    logger.setLevel(logging.INFO)

    AccessAuditLogger.log_access("analyst_test", "view_asset", "asset_123", "tenant_a")
    
    assert any("GDPR Location Access" in record.message for record in caplog.records)
    assert any("analyst_test" in record.message for record in caplog.records)


def test_api_endpoints_integration(api_client):
    """Integration tests for encryption API endpoints."""
    tracking_service.assets.clear()

    response = api_client.post("/api/v1/geospatial/update", json={
        "asset_id": "asset_api",
        "latitude": 19.0760,
        "longitude": 72.8777,
        "accuracy": 1.0
    })
    assert response.status_code == 200
    assert response.json()["status"] == "success"

    response = api_client.get("/api/v1/geospatial/assets/asset_api")
    assert response.status_code == 200
    assert response.json()["latitude"] == 19.0760
