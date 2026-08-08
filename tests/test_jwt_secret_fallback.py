"""Tests for JWT secret resolution in tenant middleware."""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.api.middleware.multi_tenancy import (
    TenantIsolationMiddleware,
    _resolve_jwt_secret,
    get_current_tenant,
)


def _build_token(secret: str, tenant_id: str = "tenant-a") -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "user-1",
        "tenant_id": tenant_id,
        "exp": now + timedelta(minutes=15),
        "iat": now,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def test_resolve_jwt_secret_prefers_aegis_over_secret_key(monkeypatch):
    monkeypatch.setenv("AEGIS_JWT_SECRET", "aegis-secret")
    monkeypatch.setenv("SECRET_KEY", "shared-secret")
    assert _resolve_jwt_secret() == "aegis-secret"


def test_resolve_jwt_secret_falls_back_to_secret_key(monkeypatch):
    monkeypatch.delenv("AEGIS_JWT_SECRET", raising=False)
    monkeypatch.setenv("SECRET_KEY", "shared-secret")
    assert _resolve_jwt_secret() == "shared-secret"


def test_middleware_accepts_secret_key_only_config(monkeypatch):
    monkeypatch.delenv("AEGIS_JWT_SECRET", raising=False)
    monkeypatch.setenv("SECRET_KEY", "shared-only-secret")

    app = FastAPI()
    app.add_middleware(TenantIsolationMiddleware)

    @app.get("/whoami")
    async def whoami(request: Request):
        return {"tenant_id": get_current_tenant()}

    token = _build_token("shared-only-secret", tenant_id="tenant-secret-key")
    with TestClient(app) as client:
        response = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["tenant_id"] == "tenant-secret-key"
