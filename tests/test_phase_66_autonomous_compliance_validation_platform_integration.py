from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.phase_66_autonomous_compliance_validation_platform.api import router

import hashlib
import pytest

ADMIN_KEY = "tenant_testco"
ADMIN_HASH = hashlib.sha256(ADMIN_KEY.encode()).hexdigest()

app = FastAPI()
app.include_router(router)
client = TestClient(app)

HEADERS = {"x-api-key": ADMIN_KEY}


@pytest.fixture(scope="module", autouse=True)
def _admin_auth():
    mp = pytest.MonkeyPatch()
    mp.setenv("AEGIS_ROLE_ADMIN", ADMIN_HASH)
    yield
    mp.undo()


def test_create_record():
    payload = {"record_id": "rec-integ-66-001", "tenant_id": "testco", "policy_id": "pol-soc2", "regulation_name": "SOC_TYPE_II", "rules_count": 42, "status": "ENFORCED"}
    resp = client.post("/api/v1/phase66/records", json=payload, headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["status"] == "RECORD_CREATED"
    assert resp.json()["record_id"] == "rec-integ-66-001"


def test_list_records():
    resp = client.get("/api/v1/phase66/records", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "records" in data
    assert data["count"] >= 1


def test_get_record():
    resp = client.get("/api/v1/phase66/records/rec-integ-66-001", headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["record_id"] == "rec-integ-66-001"


def test_analytics():
    resp = client.get("/api/v1/phase66/analytics", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_items" in data
    assert "health_score" in data
