"""Tenant resolution must only report its own failures.

The middleware wrapped ``call_next`` in its own except clause, so any exception
from a route handler was logged as "Tenant context initialization failure" and
re-raised as a TenantIsolationError. The original type, message and any handler
registered for it were lost, and an operator reading the log was pointed at the
wrong subsystem.
"""

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

import src.api.middleware.multi_tenancy as multi_tenancy
from src.api.middleware.multi_tenancy import (
    TenantIsolationError,
    TenantIsolationMiddleware,
    get_current_tenant,
)


@pytest.fixture
def client():
    app = FastAPI()
    app.add_middleware(TenantIsolationMiddleware)

    @app.get("/boom")
    async def boom():
        raise ValueError("a bug deep inside a route handler")

    @app.get("/teapot")
    async def teapot():
        raise HTTPException(status_code=418, detail="i am a teapot")

    @app.get("/tenant")
    async def tenant():
        return {"tenant": get_current_tenant()}

    return TestClient(app)


def test_a_route_exception_keeps_its_own_type(client):
    with pytest.raises(ValueError) as caught:
        client.get("/boom")

    assert not isinstance(caught.value, TenantIsolationError), (
        "a ValueError from a route handler was reported as a tenant isolation "
        "failure, which hides both the type and the cause"
    )
    assert "a bug deep inside a route handler" in str(caught.value)


def test_a_route_http_exception_keeps_its_status_and_detail(client):
    response = client.get("/teapot")

    assert response.status_code == 418
    assert response.json()["detail"] == "i am a teapot"


def test_tenant_resolution_failures_are_still_reported(client):
    """A malformed tenant header must still produce the resolution error."""
    response = client.get("/tenant", headers={"X-Tenant-ID": "not a valid tenant!"})

    assert response.status_code in (400, 401)
    assert "detail" in response.json()


def test_a_resolution_crash_is_still_reported_as_a_context_failure(client, monkeypatch):
    """The original handling must survive for the case it was written for."""
    def _explode(request):
        raise RuntimeError("resolution itself broke")

    monkeypatch.setattr(multi_tenancy, "resolve_tenant_from_request", _explode)

    with pytest.raises(TenantIsolationError) as caught:
        client.get("/tenant")

    assert caught.value.detail == "Context initialization failure"
    assert isinstance(caught.value.__cause__, RuntimeError)


def test_tenant_context_is_still_bound_during_a_request(client, monkeypatch):
    monkeypatch.setenv("AEGIS_DEFAULT_TENANT_ID", "acme")

    response = client.get("/tenant", headers={"X-API-Key": "any-key"})

    assert response.status_code == 200
    assert response.json()["tenant"] == "acme"


def test_tenant_context_is_cleared_after_a_route_raises(client, monkeypatch):
    """The finally block must still run when the handler blows up."""
    monkeypatch.setenv("AEGIS_DEFAULT_TENANT_ID", "acme")

    with pytest.raises(ValueError):
        client.get("/boom", headers={"X-API-Key": "any-key"})

    assert get_current_tenant() is None
