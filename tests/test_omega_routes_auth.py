"""Auth contract for the Omega Platform routes (src/api/omega_routes.py).

omega_routes.py was mounted without any per-route auth being applied to its
handlers. These tests pin the fix: every endpoint except /health must go
through require_role, the RBAC gate the rest of the API uses. /initialize is
restricted to SUPER_ADMIN.
"""

import hashlib

import pytest
from fastapi.testclient import TestClient

from src.api.main import app

_VALID_KEY = "test-omega-key-do-not-reuse"
_VALID_KEY_HASH = hashlib.sha256(_VALID_KEY.encode("utf-8")).hexdigest()

_GATED_ENDPOINTS = [
    ("GET", "/api/v1/omega/status"),
    ("GET", "/api/v1/omega/dashboard"),
    ("GET", "/api/v1/omega/capabilities"),
    ("GET", "/api/v1/omega/layers"),
    ("POST", "/api/v1/omega/analyze/some-entity-id"),
    ("POST", "/api/v1/omega/initialize"),
]


@pytest.fixture
def client_with_key_configured(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    # require_role authenticates against SHA-256 hashes only; the legacy plain
    # AEGIS_API_KEY variable is not consulted by the RBAC gate.
    monkeypatch.setenv("AEGIS_API_KEY_HASHES", _VALID_KEY_HASH)
    return TestClient(app)


def _call(client: TestClient, method: str, path: str, headers: dict | None = None):
    if method == "GET":
        return client.get(path, headers=headers)
    return client.post(path, json={}, headers=headers)


@pytest.mark.parametrize(("method", "path"), _GATED_ENDPOINTS)
def test_gated_endpoint_rejects_missing_key(client_with_key_configured, method, path):
    response = _call(client_with_key_configured, method, path)
    assert response.status_code == 401


@pytest.mark.parametrize(("method", "path"), _GATED_ENDPOINTS)
def test_gated_endpoint_rejects_wrong_key(client_with_key_configured, method, path):
    headers = {"X-API-Key": "not-the-configured-key"}
    response = _call(client_with_key_configured, method, path, headers)
    assert response.status_code == 401


@pytest.mark.parametrize(("method", "path"), _GATED_ENDPOINTS)
def test_gated_endpoint_accepts_valid_key(client_with_key_configured, method, path):
    headers = {"X-API-Key": _VALID_KEY}
    response = _call(client_with_key_configured, method, path, headers)
    assert response.status_code != 401


def test_health_endpoint_stays_open(client_with_key_configured):
    response = client_with_key_configured.get("/api/v1/omega/health")
    assert response.status_code == 200