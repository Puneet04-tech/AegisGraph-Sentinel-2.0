"""Regression tests for websocket auth on the fraud stream."""

from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.security import require_api_key

_VALID_KEY = "test-api-key-for-websocket-unit-tests-do-not-reuse"
_VALID_HASH = hashlib.sha256(_VALID_KEY.encode("utf-8")).hexdigest()


@pytest.fixture
def auth_enabled_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Create a client with the real API-key dependency enabled."""
    monkeypatch.setenv("AEGIS_API_KEY_HASHES", _VALID_HASH)
    saved_override = app.dependency_overrides.pop(require_api_key, None)
    try:
        with TestClient(app) as client:
            yield client
    finally:
        if saved_override is None:
            app.dependency_overrides.pop(require_api_key, None)
        else:
            app.dependency_overrides[require_api_key] = saved_override


def test_fraud_websocket_rejects_missing_api_key(
    auth_enabled_client: TestClient,
) -> None:
    """The fraud websocket must fail closed without an API key."""
    with pytest.raises(Exception):
        with auth_enabled_client.websocket_connect(
            "/api/v1/fraud/stream/test-client"
        ):
            pass


def test_fraud_websocket_accepts_valid_api_key(
    auth_enabled_client: TestClient,
) -> None:
    """A valid API key should allow the fraud websocket handshake."""
    with auth_enabled_client.websocket_connect(
        "/api/v1/fraud/stream/test-client",
        headers={"X-API-Key": _VALID_KEY},
    ) as websocket:
        websocket.send_text("ping")
        assert websocket.receive_text() == "pong"
