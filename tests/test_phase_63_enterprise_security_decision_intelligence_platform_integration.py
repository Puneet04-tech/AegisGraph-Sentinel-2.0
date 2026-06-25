from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.phase_63_enterprise_security_decision_intelligence_platform.api import router

app = FastAPI()
app.include_router(router)
client = TestClient(app)

HEADERS = {"x-api-key": "tenant_testco"}


def test_create_record():
    payload = {"record_id": "rec-integ-63-001", "tenant_id": "testco", "decision_id": "dec-777", "action_taken": "BLOCK_IP", "rationales": ["High anomalous traffic", "Known bad IP"], "confidence": 0.99}
    resp = client.post("/api/v1/phase63/records", json=payload, headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["status"] == "RECORD_CREATED"
    assert resp.json()["record_id"] == "rec-integ-63-001"


def test_list_records():
    resp = client.get("/api/v1/phase63/records", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "records" in data
    assert data["count"] >= 1


def test_get_record():
    resp = client.get("/api/v1/phase63/records/rec-integ-63-001", headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["record_id"] == "rec-integ-63-001"


def test_analytics():
    resp = client.get("/api/v1/phase63/analytics", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_items" in data
    assert "health_score" in data
