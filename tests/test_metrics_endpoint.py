import sys
from pathlib import Path
from fastapi.testclient import TestClient
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.api.main import app

client = TestClient(app)

def test_metrics_endpoint():
    """Verify that the /metrics endpoint returns Prometheus exposition format."""
    response = client.get("/metrics")
    assert response.status_code == 200
    
    # Check that some expected metrics are in the output
    text = response.text
    assert "fraud_request_count" in text
    assert "aegis_error_count" in text
    assert "fraud_request_latency_seconds" in text
    assert "model_inference_latency_seconds" in text
    assert "graph_traversal_latency_seconds" in text
    assert "neo4j_query_latency_seconds" in text
