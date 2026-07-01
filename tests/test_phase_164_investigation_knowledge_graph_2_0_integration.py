from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.phase_164_investigation_knowledge_graph_2_0.api import router

app = FastAPI()
app.include_router(router)
client = TestClient(app)

HEADERS = {"x-api-key": "tenant_testco"}


def test_create_record():
    payload = {
        "record_id": "rec-integ-164-001",
        "tenant_id": "testco",
        "name": "Phase 164 Integration Test Record",
        "status": "ACTIVE",
        "metadata": {"source": "integration_test"}
    }
    resp = client.post("/api/v1/phase164/records", json=payload, headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["status"] == "RECORD_CREATED"
    assert resp.json()["record_id"] == "rec-integ-164-001"


def test_list_records():
    resp = client.get("/api/v1/phase164/records", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "records" in data
    assert data["count"] >= 1


def test_get_record():
    resp = client.get("/api/v1/phase164/records/rec-integ-164-001", headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["record_id"] == "rec-integ-164-001"


def test_create_alert():
    payload = {
        "alert_id": "alt-integ-164-001",
        "title": "Phase 164 Test Alert",
        "severity": "HIGH",
        "is_active": True
    }
    resp = client.post("/api/v1/phase164/alerts", json=payload, headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ALERT_CREATED"


def test_analytics():
    resp = client.get("/api/v1/phase164/analytics", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_records" in data
    assert "health_score" in data
