"""Authentication tests for Phase 173 Security Forecasting and Prediction Engine.

Tests verify that:
- Placeholder authentication (tenant_ prefix, SUPER_ADMIN bypass) is removed
- Only valid API keys with ADMIN role can access endpoints
- Tenant context is properly resolved from authenticated credentials
- Unauthorized requests are rejected with appropriate error codes
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.phase_173_security_forecasting_and_prediction_engine.api import router
from src.api.middleware.multi_tenancy import set_current_tenant, clear_current_tenant

import hashlib
import pytest

ADMIN_KEY = "test_admin_key_173"
ADMIN_HASH = hashlib.sha256(ADMIN_KEY.encode()).hexdigest()

INVALID_KEY = "invalid_key"
VIEWER_KEY = "viewer_key_173"
VIEWER_HASH = hashlib.sha256(VIEWER_KEY.encode()).hexdigest()

app = FastAPI()
app.include_router(router)
client = TestClient(app)

VALID_HEADERS = {"X-API-Key": ADMIN_KEY}
INVALID_HEADERS = {"X-API-Key": INVALID_KEY}
VIEWER_HEADERS = {"X-API-Key": VIEWER_KEY}


@pytest.fixture(scope="module", autouse=True)
def _configure_auth():
    """Configure role-based authentication for tests."""
    mp = pytest.MonkeyPatch()
    mp.setenv("AEGIS_ROLE_ADMIN", ADMIN_HASH)
    mp.setenv("AEGIS_ROLE_VIEWER", VIEWER_HASH)
    yield
    mp.undo()


@pytest.fixture(autouse=True)
def _clear_tenant_context():
    """Ensure clean tenant context for each test."""
    clear_current_tenant()
    yield
    clear_current_tenant()


def test_create_record_with_valid_auth():
    """Test that valid ADMIN key can create records."""
    set_current_tenant("test_tenant")
    payload = {
        "record_id": "rec-173-001",
        "tenant_id": "test_tenant",
        "name": "Test Record",
        "status": "active",
        "metadata": {}
    }
    resp = client.post("/api/v1/phase173/records", json=payload, headers=VALID_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["status"] == "RECORD_CREATED"


def test_create_record_without_auth():
    """Test that requests without API key are rejected."""
    payload = {
        "record_id": "rec-173-002",
        "tenant_id": "test_tenant",
        "name": "Test Record",
        "status": "active"
    }
    resp = client.post("/api/v1/phase173/records", json=payload)
    assert resp.status_code == 401


def test_create_record_with_invalid_key():
    """Test that requests with invalid API key are rejected."""
    payload = {
        "record_id": "rec-173-003",
        "tenant_id": "test_tenant",
        "name": "Test Record",
        "status": "active"
    }
    resp = client.post("/api/v1/phase173/records", json=payload, headers=INVALID_HEADERS)
    assert resp.status_code == 401


def test_create_record_with_viewer_role():
    """Test that VIEWER role cannot access ADMIN-only endpoints."""
    set_current_tenant("test_tenant")
    payload = {
        "record_id": "rec-173-004",
        "tenant_id": "test_tenant",
        "name": "Test Record",
        "status": "active"
    }
    resp = client.post("/api/v1/phase173/records", json=payload, headers=VIEWER_HEADERS)
    assert resp.status_code == 403


def test_placeholder_tenant_prefix_rejected():
    """Test that placeholder 'tenant_' prefix authentication is removed."""
    # Old vulnerable pattern: any key starting with "tenant_" would work
    placeholder_headers = {"X-API-Key": "tenant_arbitrary_tenant_id"}
    payload = {
        "record_id": "rec-173-005",
        "tenant_id": "test_tenant",
        "name": "Test Record",
        "status": "active"
    }
    resp = client.post("/api/v1/phase173/records", json=payload, headers=placeholder_headers)
    # Should be rejected since the key hash is not configured
    assert resp.status_code == 401


def test_super_admin_bypass_removed():
    """Test that hardcoded SUPER_ADMIN bypass is removed."""
    # Old vulnerable pattern: "SUPER_ADMIN" string granted system access
    super_admin_headers = {"X-API-Key": "SUPER_ADMIN"}
    payload = {
        "record_id": "rec-173-006",
        "tenant_id": "test_tenant",
        "name": "Test Record",
        "status": "active"
    }
    resp = client.post("/api/v1/phase173/records", json=payload, headers=super_admin_headers)
    # Should be rejected since "SUPER_ADMIN" is not a valid configured key
    assert resp.status_code == 401


def test_list_records_with_valid_auth():
    """Test that valid ADMIN key can list records."""
    set_current_tenant("test_tenant")
    resp = client.get("/api/v1/phase173/records", headers=VALID_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "records" in data
    assert "tenant_id" in data


def test_list_records_without_auth():
    """Test that listing records without auth is rejected."""
    resp = client.get("/api/v1/phase173/records")
    assert resp.status_code == 401


def test_get_record_with_valid_auth():
    """Test that valid ADMIN key can get specific record."""
    set_current_tenant("test_tenant")
    resp = client.get("/api/v1/phase173/records/rec-173-001", headers=VALID_HEADERS)
    # May be 404 if record doesn't exist, but should not be 401/403
    assert resp.status_code in [200, 404]


def test_get_record_without_auth():
    """Test that getting record without auth is rejected."""
    resp = client.get("/api/v1/phase173/records/rec-173-001")
    assert resp.status_code == 401


def test_create_alert_with_valid_auth():
    """Test that valid ADMIN key can create alerts."""
    set_current_tenant("test_tenant")
    payload = {
        "alert_id": "alert-173-001",
        "title": "Test Alert",
        "severity": "high"
    }
    resp = client.post("/api/v1/phase173/alerts", json=payload, headers=VALID_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ALERT_CREATED"


def test_create_alert_without_auth():
    """Test that creating alerts without auth is rejected."""
    payload = {
        "alert_id": "alert-173-002",
        "title": "Test Alert",
        "severity": "high"
    }
    resp = client.post("/api/v1/phase173/alerts", json=payload)
    assert resp.status_code == 401


def test_analytics_with_valid_auth():
    """Test that valid ADMIN key can access analytics."""
    set_current_tenant("test_tenant")
    resp = client.get("/api/v1/phase173/analytics", headers=VALID_HEADERS)
    assert resp.status_code == 200


def test_analytics_without_auth():
    """Test that accessing analytics without auth is rejected."""
    resp = client.get("/api/v1/phase173/analytics")
    assert resp.status_code == 401


def test_tenant_mismatch_protection():
    """Test that tenant mismatch is still enforced after auth fix."""
    set_current_tenant("tenant_a")
    payload = {
        "record_id": "rec-173-007",
        "tenant_id": "tenant_b",  # Different from context tenant
        "name": "Test Record",
        "status": "active"
    }
    resp = client.post("/api/v1/phase173/records", json=payload, headers=VALID_HEADERS)
    assert resp.status_code == 403
    assert "Tenant mismatch" in resp.json()["detail"]


def test_tenant_context_required():
    """Test that tenant context is required for authenticated requests."""
    # Clear tenant context to simulate missing context
    clear_current_tenant()
    payload = {
        "record_id": "rec-173-008",
        "tenant_id": "test_tenant",
        "name": "Test Record",
        "status": "active"
    }
    resp = client.post("/api/v1/phase173/records", json=payload, headers=VALID_HEADERS)
    assert resp.status_code == 401
    assert "Tenant context not available" in resp.json()["detail"]
