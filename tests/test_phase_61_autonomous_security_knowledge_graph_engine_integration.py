from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.phase_61_autonomous_security_knowledge_graph_engine.api import router

app = FastAPI()
app.include_router(router)
client = TestClient(app)

HEADERS = {"x-api-key": "tenant_testco"}


def test_create_record():
    payload = {"record_id": "rec-integ-61-001", "tenant_id": "testco", "relation_id": "rel-123", "source_entity": "entity-A", "target_entity": "entity-B", "relation_type": "FRIEND", "confidence": 0.95}
    resp = client.post("/api/v1/phase61/records", json=payload, headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["status"] == "RECORD_CREATED"
    assert resp.json()["record_id"] == "rec-integ-61-001"


def test_list_records():
    resp = client.get("/api/v1/phase61/records", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "records" in data
    assert data["count"] >= 1


def test_get_record():
    resp = client.get("/api/v1/phase61/records/rec-integ-61-001", headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["record_id"] == "rec-integ-61-001"


def test_analytics():
    resp = client.get("/api/v1/phase61/analytics", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_items" in data
    assert "health_score" in data
