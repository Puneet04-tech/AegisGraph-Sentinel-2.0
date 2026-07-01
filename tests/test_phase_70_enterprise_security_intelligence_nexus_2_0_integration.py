from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.phase_70_enterprise_security_intelligence_nexus_2_0.api import router

app = FastAPI()
app.include_router(router)
client = TestClient(app)

HEADERS = {"x-api-key": "tenant_testco"}


def test_create_record():
    payload = {"record_id": "rec-integ-70-001", "tenant_id": "testco", "hub_id": "nexus-hub-primary", "connected_domains": ["fraud", "cyber", "compliance", "AML"], "ingestion_rate": 4500.5, "is_healthy": True}
    resp = client.post("/api/v1/phase70/records", json=payload, headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["status"] == "RECORD_CREATED"
    assert resp.json()["record_id"] == "rec-integ-70-001"


def test_list_records():
    resp = client.get("/api/v1/phase70/records", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "records" in data
    assert data["count"] >= 1


def test_get_record():
    resp = client.get("/api/v1/phase70/records/rec-integ-70-001", headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["record_id"] == "rec-integ-70-001"


def test_analytics():
    resp = client.get("/api/v1/phase70/analytics", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_items" in data
    assert "health_score" in data
