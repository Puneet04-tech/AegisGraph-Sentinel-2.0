from fastapi.testclient import TestClient
from src.api.main import app

def test_prometheus_metrics():
    client = TestClient(app)
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "aegis_api_latency_seconds" in response.text
