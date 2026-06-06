"""Unit tests for Role-Based Access Control (RBAC) in AegisGraph Sentinel 2.0."""

from __future__ import annotations

import hashlib
import pytest
from fastapi.testclient import TestClient
from src.api.security import Role

# Setup key and hash mappings for testing
ROLE_KEYS = {
    "SUPER_ADMIN": "test-key-super-admin",
    "ADMIN": "test-key-admin",
    "ANALYST": "test-key-analyst",
    "AUDITOR": "test-key-auditor",
    "VIEWER": "test-key-viewer",
    "GENERIC": "test-key-generic",  # Mapped to AEGIS_API_KEY_HASHES, should default to SUPER_ADMIN/VIEWER logic
}

ROLE_HASHES = {
    role: hashlib.sha256(key.encode("utf-8")).hexdigest()
    for role, key in ROLE_KEYS.items()
}


@pytest.fixture
def rbac_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Configures environment variables for RBAC testing and returns a TestClient.

    Uses monkeypatch to set role-specific environment variables in isolation.
    """
    monkeypatch.setenv("AEGIS_ROLE_SUPER_ADMIN", ROLE_HASHES["SUPER_ADMIN"])
    monkeypatch.setenv("AEGIS_ROLE_ADMIN", ROLE_HASHES["ADMIN"])
    monkeypatch.setenv("AEGIS_ROLE_ANALYST", ROLE_HASHES["ANALYST"])
    monkeypatch.setenv("AEGIS_ROLE_AUDITOR", ROLE_HASHES["AUDITOR"])
    monkeypatch.setenv("AEGIS_ROLE_VIEWER", ROLE_HASHES["VIEWER"])
    # Do not set AEGIS_API_KEY_HASHES here to test role isolation precisely, 
    # but we can set it to GENERIC for default viewer test.
    monkeypatch.setenv("AEGIS_API_KEY_HASHES", ROLE_HASHES["GENERIC"])

    from src.api.main import app
    return TestClient(app)


# ────────────────────────────────────────────────────────────
# Missing & Invalid API Key tests
# ────────────────────────────────────────────────────────────

def test_missing_credentials_returns_401(rbac_client: TestClient) -> None:
    """Requests without an X-API-Key header should fail with 401."""
    response = rbac_client.get("/api/v1/model/info")
    assert response.status_code == 401
    assert "Missing X-API-Key header" in response.json()["error"]["message"]


def test_invalid_credentials_returns_401(rbac_client: TestClient) -> None:
    """Requests with an invalid/unconfigured API key should fail with 401 in require_role."""
    headers = {"X-API-Key": "invalid-non-matching-key"}
    # Endpoint using require_role (VIEWER)
    response = rbac_client.get("/api/v1/model/info", headers=headers)
    assert response.status_code == 401
    assert "Invalid API key" in response.json()["error"]["message"]


# ────────────────────────────────────────────────────────────
# Successful & Failed Authorization tests per endpoint tier
# ────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("key_name", "expected_status"),
    [
        ("SUPER_ADMIN", 200),
        ("ADMIN", 200),
        ("ANALYST", 403),
        ("AUDITOR", 403),
        ("VIEWER", 403),
        # GENERIC key defaults to SUPER_ADMIN so it will pass the Admin gate (200 equivalent)
        ("GENERIC", 200),
    ]
)
def test_admin_routes_authorization(rbac_client: TestClient, key_name: str, expected_status: int) -> None:
    """Honeypot active endpoint (Admin-only) is only accessible by ADMIN and SUPER_ADMIN."""
    headers = {
        "X-API-Key": ROLE_KEYS[key_name],
    }
    response = rbac_client.post("/api/v1/blockchain/export", headers=headers, json={"evidence_id": "test"})
    if expected_status == 200:
        assert response.status_code != 403, f"{key_name} should have passed the Admin RBAC gate"
    else:
        assert response.status_code == 403, f"{key_name} should be blocked by Admin RBAC gate with 403"


@pytest.mark.parametrize(
    ("key_name", "expected_status"),
    [
        ("SUPER_ADMIN", 200),
        ("ADMIN", 200),
        ("ANALYST", 200),
        ("AUDITOR", 403),
        ("VIEWER", 403),
        ("GENERIC", 200),
    ]
)
def test_analyst_routes_authorization(rbac_client: TestClient, key_name: str, expected_status: int) -> None:
    """Fraud check endpoint (Analyst) is accessible by ANALYST, ADMIN, and SUPER_ADMIN."""
    headers = {"X-API-Key": ROLE_KEYS[key_name]}
    response = rbac_client.post("/api/v1/fraud/check", headers=headers, json={})
    if expected_status == 200:
        assert response.status_code not in (401, 403), f"{key_name} should pass Analyst gate"
    else:
        assert response.status_code == 403, f"{key_name} should be blocked by Analyst gate with 403"


@pytest.mark.parametrize(
    ("key_name", "expected_status"),
    [
        ("SUPER_ADMIN", 200),
        ("ADMIN", 200),
        ("ANALYST", 403),
        ("AUDITOR", 200),
        ("VIEWER", 403),
        ("GENERIC", 200),
    ]
)
def test_auditor_routes_authorization(rbac_client: TestClient, key_name: str, expected_status: int) -> None:
    """Stats endpoint (Auditor) is accessible by AUDITOR, ADMIN, and SUPER_ADMIN."""
    headers = {"X-API-Key": ROLE_KEYS[key_name]}
    response = rbac_client.get("/stats", headers=headers)
    if expected_status == 200:
        assert response.status_code not in (401, 403), f"{key_name} should pass Auditor gate"
    else:
        assert response.status_code == 403, f"{key_name} should be blocked by Auditor gate with 403"


@pytest.mark.parametrize(
    ("key_name", "expected_status"),
    [
        ("SUPER_ADMIN", 200),
        ("ADMIN", 200),
        ("ANALYST", 200),
        ("AUDITOR", 200),
        ("VIEWER", 200),
        ("GENERIC", 200),
    ]
)
def test_viewer_routes_authorization(rbac_client: TestClient, key_name: str, expected_status: int) -> None:
    """Model info endpoint (Viewer) is accessible by everyone, including GENERIC key default VIEWER/SUPER_ADMIN role."""
    headers = {"X-API-Key": ROLE_KEYS[key_name]}
    response = rbac_client.get("/api/v1/model/info", headers=headers)
    assert response.status_code == 200, f"{key_name} should pass Viewer gate with 200"
