import pytest
from fastapi.testclient import TestClient
import sys
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.api.main import app, state, LRUCache
client = TestClient(app)

_TEST_ADMIN_TOKEN = "test-api-key-for-health-tests"
_TEST_ADMIN_TOKEN_HASH = hashlib.sha256(_TEST_ADMIN_TOKEN.encode("utf-8")).hexdigest()

def test_centrality_baseline_lru_cache():
    """Ensure centrality_baseline evicts old items and limits size to maxsize."""
    # Temporarily set maxsize to a small value for testing
    original_cache = state.centrality_baseline
    state.centrality_baseline = LRUCache(maxsize=3)
    
    # Add 4 items
    state.centrality_baseline["acc_1"] = [0.1]
    state.centrality_baseline["acc_2"] = [0.2]
    state.centrality_baseline["acc_3"] = [0.3]
    state.centrality_baseline["acc_4"] = [0.4]
    
    # Check that it is capped at 3 items
    assert len(state.centrality_baseline) == 3
    
    # acc_1 should have been evicted because it was added first
    assert "acc_1" not in state.centrality_baseline
    assert "acc_4" in state.centrality_baseline
    
    # Access acc_2 to refresh its LRU status
    _ = state.centrality_baseline["acc_2"]
    
    # Add a 5th item
    state.centrality_baseline["acc_5"] = [0.5]
    
    # Check that acc_3 was evicted (since acc_2 was just accessed)
    assert "acc_3" not in state.centrality_baseline
    assert "acc_2" in state.centrality_baseline
    assert "acc_5" in state.centrality_baseline
    
    # Restore original cache
    state.centrality_baseline = original_cache

def test_memory_diagnostics_endpoint(monkeypatch):
    """Ensure the monitoring endpoint returns memory info without errors."""
    monkeypatch.setenv("ADMIN_API_KEY", _TEST_ADMIN_TOKEN_HASH)
    headers = {"Authorization": f"Bearer {_TEST_ADMIN_TOKEN}"}
    
    response = client.get("/api/v1/monitoring/memory", headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "ok"
    assert "memory" in data
    assert "caches" in data
    assert "globals" in data
    
    assert data["caches"]["centrality_baseline_maxsize"] == 10000
