"""The OpenAPI document must agree with the auth the application enforces.

FastAPI records a security requirement only for a dependency built on a
SecurityBase, which is what require_role uses. Calling a verification helper
inside the handler body enforces auth at runtime but leaves the operation
documented as public, so Swagger shows no padlock and a generated client omits
the key.
"""

import hashlib
import re

import pytest
from fastapi.testclient import TestClient

from src.api.main import app

ANALYST_KEY = "openapi-contract-test-key"

# Documented as public and genuinely public. Everything else that rejects an
# anonymous caller must also declare a security requirement.
PUBLIC_PATHS = {
    "/",
    "/health",
    "/health/liveness",
    "/health/readiness",
    "/api/v1/health",
    "/metrics",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/v1/agents/health",
    "/api/v1/archival/health",
    "/api/v1/decision/health",
}

UNAUTHENTICATED = {401, 403, 503}


@pytest.fixture(autouse=True)
def _auth_configured(monkeypatch):
    digest = hashlib.sha256(ANALYST_KEY.encode()).hexdigest()
    for role in ("ANALYST", "ADMIN", "AUDITOR", "VIEWER"):
        monkeypatch.setenv(f"AEGIS_ROLE_{role}", digest)
    monkeypatch.setenv("AEGIS_API_KEY_HASHES", digest)
    from src.api.security import _invalidate_auth_cache

    _invalidate_auth_cache()
    yield
    _invalidate_auth_cache()


def _operations_without_declared_security():
    spec = app.openapi()
    for path, operations in spec["paths"].items():
        for method, operation in operations.items():
            if not operation.get("security"):
                yield method.upper(), path


def test_openapi_declares_security_for_everything_it_enforces():
    """No operation may enforce auth while documenting itself as public."""
    client = TestClient(app)
    undeclared = []

    for method, path in _operations_without_declared_security():
        if path in PUBLIC_PATHS:
            continue
        concrete = re.sub(r"\{[^}]+\}", "probe-value", path)
        try:
            response = client.request(method, concrete, json={})
        except Exception:
            continue
        if response.status_code in UNAUTHENTICATED:
            undeclared.append((method, path, response.status_code))

    assert not undeclared, (
        "These operations reject an anonymous caller but declare no security "
        f"requirement, so Swagger shows them as public: {undeclared}. Gate them "
        "with require_role rather than calling a verifier inside the handler."
    )


def test_agent_operations_declare_security():
    spec = app.openapi()
    undeclared = [
        (method.upper(), path)
        for path, operations in spec["paths"].items()
        if path.startswith("/api/v1/agents")
        for method, operation in operations.items()
        if not operation.get("security") and path not in PUBLIC_PATHS
    ]

    assert not undeclared, f"agent operations missing a security requirement: {undeclared}"


def test_agent_health_stays_public():
    assert TestClient(app).get("/api/v1/agents/health").status_code == 200


def test_agent_endpoint_rejects_anonymous_and_accepts_a_valid_key():
    client = TestClient(app)

    assert client.get("/api/v1/agents/stats").status_code == 401
    assert (
        client.get("/api/v1/agents/stats", headers={"X-API-Key": ANALYST_KEY}).status_code
        == 200
    )
