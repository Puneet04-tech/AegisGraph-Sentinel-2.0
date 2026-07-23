from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from src.api.middleware.multi_tenancy import (
    TenantIsolationMiddleware,
    clear_current_tenant,
    get_current_tenant,
)
from src.db.tenant_isolation import TenantScopedNeo4jSession, get_tenant_db


def _build_token(secret: str, *, tenant_id: str | None = None, org: str | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "user-1",
        "email": "user@example.com",
        "role": "member",
        "permissions": ["read"],
        "exp": now + timedelta(minutes=15),
        "iat": now,
        "jti": "jti-1",
    }
    if tenant_id is not None:
        payload["tenant_id"] = tenant_id
    if org is not None:
        payload["org"] = org
    return jwt.encode(payload, secret, algorithm="HS256")


@pytest.fixture
def tenant_app(monkeypatch):
    monkeypatch.setenv("AEGIS_JWT_SECRET", "test-tenant-secret")
    app = FastAPI()
    app.add_middleware(TenantIsolationMiddleware)

    @app.get("/whoami")
    async def whoami(request: Request):
        return {
            "tenant_id": get_current_tenant(),
            "state_tenant_id": getattr(request.state, "tenant_id", None),
            "state_tenant_source": getattr(request.state, "tenant_source", None),
        }

    return app


def test_valid_tenant_access_from_jwt(tenant_app):
    token = _build_token("test-tenant-secret", tenant_id="tenant-a")
    with TestClient(tenant_app) as client:
        response = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["tenant_id"] == "tenant-a"
    assert get_current_tenant() is None


def test_missing_tenant_is_rejected_for_authenticated_request(tenant_app):
    token = _build_token("test-tenant-secret")
    with TestClient(tenant_app) as client:
        response = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert "Tenant information is missing from JWT" in response.text
    assert get_current_tenant() is None


def test_invalid_tenant_is_rejected(tenant_app):
    token = _build_token("test-tenant-secret", tenant_id="tenant-a")
    with TestClient(tenant_app) as client:
        response = client.get(
            "/whoami",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Tenant-ID": "bad tenant id!",
            },
        )

    assert response.status_code == 400
    assert "Malformed tenant identifier" in response.text
    assert get_current_tenant() is None


@pytest.mark.anyio
async def test_concurrent_requests_do_not_leak_tenant_context(tenant_app):
    token_a = _build_token("test-tenant-secret", tenant_id="tenant-a")
    token_b = _build_token("test-tenant-secret", org="tenant-b")

    transport = ASGITransport(app=tenant_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async def fetch(token: str):
            response = await client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
            assert response.status_code == 200
            return response.json()["tenant_id"]

        tenant_a, tenant_b = await asyncio.gather(fetch(token_a), fetch(token_b))

    assert {tenant_a, tenant_b} == {"tenant-a", "tenant-b"}
    assert get_current_tenant() is None


def test_cross_tenant_access_is_denied(tenant_app):
    token = _build_token("test-tenant-secret", tenant_id="tenant-a")
    with TestClient(tenant_app) as client:
        response = client.get(
            "/whoami",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Tenant-ID": "tenant-b",
            },
        )

    assert response.status_code == 403
    assert "Unauthorized tenant access" in response.text
    assert get_current_tenant() is None


def test_tenant_db_wraps_session(monkeypatch):
    class DummySession:
        def __init__(self):
            self.calls = []

        def run(self, query, **params):
            self.calls.append((query, params))
            return {"query": query, "params": params}

    dummy_session = DummySession()
    wrapper = TenantScopedNeo4jSession(dummy_session, tenant_id="tenant-1")
    result = wrapper.run("MATCH (n) RETURN n", foo="bar")

    assert result["params"]["tenant_id"] == "tenant-1"
    assert result["params"]["foo"] == "bar"
