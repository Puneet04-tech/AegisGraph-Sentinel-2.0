from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.phase_62_cross_domain_investigation_orchestrator.api import router

app = FastAPI()
app.include_router(router)
client = TestClient(app)

HEADERS = {"x-api-key": "tenant_testco"}


def test_create_record():
    payload = {"record_id": "rec-integ-62-001", "tenant_id": "testco", "workflow_id": "wf-111", "domain": "cyber", "current_state": "IN_PROGRESS", "assigned_analyst": "analyst-x"}
    resp = client.post("/api/v1/phase62/records", json=payload, headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["status"] == "RECORD_CREATED"
    assert resp.json()["record_id"] == "rec-integ-62-001"


def test_list_records():
    resp = client.get("/api/v1/phase62/records", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "records" in data
    assert data["count"] >= 1


def test_get_record():
    resp = client.get("/api/v1/phase62/records/rec-integ-62-001", headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["record_id"] == "rec-integ-62-001"


def test_analytics():
    resp = client.get("/api/v1/phase62/analytics", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_items" in data
    assert "health_score" in data
