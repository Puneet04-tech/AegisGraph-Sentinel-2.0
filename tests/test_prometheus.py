import os
import hashlib
import pytest
from fastapi.testclient import TestClient
from src.api.main import app, state
from src.config.loaders import load_settings


@pytest.fixture
def production_settings(monkeypatch):
    """Point the app at a production runtime configuration for one test."""
    monkeypatch.setattr(
        state,
        "settings",
        load_settings(environ={"AEGIS_ENV": "production"}),
    )


def test_prometheus_metrics_unauthenticated_no_token_configured(monkeypatch):
    # Outside production an unset token leaves the endpoint open for local scraping
    monkeypatch.delenv("AEGIS_METRICS_SCRAPE_TOKEN_HASH", raising=False)
    client = TestClient(app)
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "aegis_api_latency_seconds" in response.text


def test_prometheus_metrics_unconfigured_in_production_is_refused(
    monkeypatch, production_settings
):
    # In production an unset token must not fall back to anonymous access
    monkeypatch.delenv("AEGIS_METRICS_SCRAPE_TOKEN_HASH", raising=False)
    client = TestClient(app)
    response = client.get("/metrics")
    assert response.status_code == 503
    assert "AEGIS_METRICS_SCRAPE_TOKEN_HASH" in response.text


def test_prometheus_metrics_configured_in_production_still_authenticates(
    monkeypatch, production_settings
):
    # A configured token keeps working in production
    test_token = "prod-scrape-token"
    monkeypatch.setenv(
        "AEGIS_METRICS_SCRAPE_TOKEN_HASH",
        hashlib.sha256(test_token.encode()).hexdigest(),
    )
    client = TestClient(app)

    assert client.get("/metrics").status_code == 401
    response = client.get("/metrics", headers={"Authorization": f"Bearer {test_token}"})
    assert response.status_code == 200
    assert "aegis_api_latency_seconds" in response.text

def test_prometheus_metrics_authenticated_with_token_configured(monkeypatch):
    # When a token is configured, it should require auth
    test_token = "secret123"
    token_hash = hashlib.sha256(test_token.encode()).hexdigest()
    
    # We set the environment variable so os.getenv reads it dynamically
    monkeypatch.setenv("AEGIS_METRICS_SCRAPE_TOKEN_HASH", token_hash)
    
    client = TestClient(app)
    
    # 1. No token -> 401
    response = client.get("/metrics")
    assert response.status_code == 401
    
    # 2. Wrong token -> 401
    response = client.get("/metrics", headers={"Authorization": "Bearer wrong"})
    assert response.status_code == 401
    
    # 3. Correct token -> 200
    response = client.get("/metrics", headers={"Authorization": f"Bearer {test_token}"})
    assert response.status_code == 200
    assert "aegis_api_latency_seconds" in response.text
