import os
import hashlib
from fastapi.testclient import TestClient
from src.api.main import app

def test_prometheus_metrics_unauthenticated_no_token_configured():
    # When no token is configured, it should be open
    client = TestClient(app)
    response = client.get("/metrics")
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
