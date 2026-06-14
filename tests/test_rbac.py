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


# ────────────────────────────────────────────────────────────
# Issue #634: Explicit Admin vs Analyst RBAC scenarios
# ────────────────────────────────────────────────────────────

# Admin-only endpoints: honeypot management, memory diagnostics,
# blockchain export (legal proceedings), and case status mutations.
_ADMIN_ONLY_ENDPOINTS = [
    # Honeypot admin endpoints
    ("GET",  "/api/v1/honeypot/active"),
    ("GET",  "/api/v1/honeypot/stats"),
    # Memory diagnostics
    ("GET",  "/api/v1/monitoring/memory"),
    # Blockchain legal export (requires additional tokens; auth gate fires first)
    ("POST", "/api/v1/blockchain/export"),
    # Privileged case status mutation
    ("PATCH", "/api/v1/cases/any-case-id"),
]

# Analyst-accessible read/detect endpoints (Issue #634 § 6)
_ANALYST_READABLE_ENDPOINTS = [
    ("POST", "/api/v1/fraud/check"),
    ("GET",  "/api/v1/model/info"),
]


@pytest.mark.parametrize(("method", "path"), _ADMIN_ONLY_ENDPOINTS)
def test_admin_can_access_admin_only_endpoints(
    rbac_client: TestClient,
    method: str,
    path: str,
) -> None:
    """Issue #634: Admin keys must NOT receive 403 on admin-only endpoints.

    The downstream handler may still return 4xx/5xx for missing bodies or
    unconfigured services, but the RBAC gate itself must let admin through.
    """
    headers = {"X-API-Key": ROLE_KEYS["ADMIN"]}
    if method == "GET":
        resp = rbac_client.get(path, headers=headers)
    elif method == "POST":
        resp = rbac_client.post(path, headers=headers, json={})
    else:  # PATCH
        resp = rbac_client.patch(path, headers=headers, json={})
    assert resp.status_code != 403, (
        f"ADMIN key should pass the RBAC gate for {method} {path}; "
        f"got {resp.status_code}. Body: {resp.text}"
    )


@pytest.mark.parametrize(("method", "path"), _ADMIN_ONLY_ENDPOINTS)
def test_analyst_gets_403_on_admin_only_endpoints(
    rbac_client: TestClient,
    method: str,
    path: str,
) -> None:
    """Issue #634: Analyst keys must receive 403 on admin-only endpoints."""
    headers = {"X-API-Key": ROLE_KEYS["ANALYST"]}
    if method == "GET":
        resp = rbac_client.get(path, headers=headers)
    elif method == "POST":
        resp = rbac_client.post(path, headers=headers, json={})
    else:  # PATCH
        resp = rbac_client.patch(path, headers=headers, json={})
    assert resp.status_code == 403, (
        f"ANALYST key should be blocked with 403 on {method} {path}; "
        f"got {resp.status_code}. Body: {resp.text}"
    )


@pytest.mark.parametrize(("method", "path"), _ADMIN_ONLY_ENDPOINTS)
def test_unauthenticated_gets_401_on_admin_only_endpoints(
    rbac_client: TestClient,
    method: str,
    path: str,
) -> None:
    """Issue #634: Requests without any API key must receive 401."""
    if method == "GET":
        resp = rbac_client.get(path)
    elif method == "POST":
        resp = rbac_client.post(path, json={})
    else:  # PATCH
        resp = rbac_client.patch(path, json={})
    assert resp.status_code == 401, (
        f"Unauthenticated request to {method} {path} should be 401; "
        f"got {resp.status_code}. Body: {resp.text}"
    )


@pytest.mark.parametrize(("method", "path"), _ANALYST_READABLE_ENDPOINTS)
def test_analyst_can_access_analyst_endpoints(
    rbac_client: TestClient,
    method: str,
    path: str,
) -> None:
    """Issue #634 § 6: Analyst keys must not be blocked on read/detect endpoints."""
    headers = {"X-API-Key": ROLE_KEYS["ANALYST"]}
    if method == "GET":
        resp = rbac_client.get(path, headers=headers)
    else:
        resp = rbac_client.post(path, headers=headers, json={})
    assert resp.status_code not in (401, 403), (
        f"ANALYST key should not be blocked by RBAC on {method} {path}; "
        f"got {resp.status_code}. Body: {resp.text}"
    )


# ────────────────────────────────────────────────────────────
# require_any_role and require_admin helper smoke tests
# ────────────────────────────────────────────────────────────

def test_require_any_role_accepts_analyst_on_analyst_endpoint(
    rbac_client: TestClient,
) -> None:
    """require_any_role is a transparent alias: analyst passes an analyst gate."""
    headers = {"X-API-Key": ROLE_KEYS["ANALYST"]}
    # /api/v1/model/info is gated at VIEWER level (analyst inherits viewer)
    resp = rbac_client.get("/api/v1/model/info", headers=headers)
    assert resp.status_code == 200


def test_require_admin_blocks_analyst(
    rbac_client: TestClient,
) -> None:
    """require_admin() blocks analyst keys — honeypot/active is the canonical admin route."""
    headers = {"X-API-Key": ROLE_KEYS["ANALYST"]}
    resp = rbac_client.get("/api/v1/honeypot/active", headers=headers)
    assert resp.status_code == 403


def test_require_admin_allows_super_admin(
    rbac_client: TestClient,
) -> None:
    """require_admin() accepts SUPER_ADMIN via role inheritance."""
    headers = {"X-API-Key": ROLE_KEYS["SUPER_ADMIN"]}
    resp = rbac_client.get("/api/v1/monitoring/memory", headers=headers)
    # SUPER_ADMIN inherits ADMIN; gate passes. Downstream may be 200 or 500.
    assert resp.status_code != 403, (
        f"SUPER_ADMIN should not receive 403 on /api/v1/monitoring/memory; "
        f"got {resp.status_code}. Body: {resp.text}"
    )


def test_error_response_contains_message_field(
    rbac_client: TestClient,
) -> None:
    """Issue #634: 403 response must include a JSON error.message field."""
    headers = {"X-API-Key": ROLE_KEYS["ANALYST"]}
    resp = rbac_client.get("/api/v1/honeypot/active", headers=headers)
    assert resp.status_code == 403
    body = resp.json()
    # The exception handlers in register_exception_handlers() wrap the detail
    # under {"error": {"code": ..., "message": ...}}.
    assert "error" in body, f"Expected 'error' key in response body: {body}"
    error_block = body["error"]
    assert "message" in error_block, f"Expected 'message' in error block: {error_block}"


def test_analyst_gets_403_on_verbose_health(rbac_client: TestClient) -> None:
    """Issue #634: Verbose health info is admin-only; Analyst must get 403."""
    headers = {"X-API-Key": ROLE_KEYS["ANALYST"]}
    resp = rbac_client.get("/api/v1/health?verbose=true", headers=headers)
    assert resp.status_code == 403, (
        f"ANALYST should be blocked on verbose health; got {resp.status_code}. Body: {resp.text}"
    )
    resp2 = rbac_client.get("/health?verbose=true", headers=headers)
    assert resp2.status_code == 403, (
        f"ANALYST should be blocked on /health?verbose=true; got {resp2.status_code}. Body: {resp2.text}"
    )


def test_admin_can_access_verbose_health(rbac_client: TestClient) -> None:
    """Issue #634: Admin must pass verbose health RBAC gate."""
    headers = {"X-API-Key": ROLE_KEYS["ADMIN"]}
    resp = rbac_client.get("/api/v1/health?verbose=true", headers=headers)
    assert resp.status_code not in (401, 403), (
        f"ADMIN should pass verbose health RBAC gate; got {resp.status_code}. Body: {resp.text}"
    )
    resp2 = rbac_client.get("/health?verbose=true", headers=headers)
    assert resp2.status_code not in (401, 403), (
        f"ADMIN should pass /health?verbose=true RBAC gate; got {resp2.status_code}. Body: {resp2.text}"
    )


def test_unauthenticated_gets_401_on_verbose_health(rbac_client: TestClient) -> None:
    """Issue #634: Unauthenticated request to verbose health must be 401."""
    resp = rbac_client.get("/api/v1/health?verbose=true")
    assert resp.status_code == 401, (
        f"Unauthenticated verbose health should be 401; got {resp.status_code}. Body: {resp.text}"
    )
    resp2 = rbac_client.get("/health?verbose=true")
    assert resp2.status_code == 401, (
        f"Unauthenticated /health?verbose=true should be 401; got {resp2.status_code}. Body: {resp2.text}"
    )


def test_health_without_verbose_is_public(rbac_client: TestClient) -> None:
    """Non-verbose health endpoint must not require authentication."""
    resp = rbac_client.get("/api/v1/health")
    assert resp.status_code == 200, (
        f"Non-verbose health should be public; got {resp.status_code}. Body: {resp.text}"
    )
    resp2 = rbac_client.get("/health")
    assert resp2.status_code == 200, (
        f"Non-verbose health should be public; got {resp2.status_code}. Body: {resp2.text}"
    )
