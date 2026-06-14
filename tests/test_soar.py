import pytest
import hashlib
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from src.api.main import app
from src.soar import get_soar_service, get_store
from src.soar.models import (
    ThreatSeverity,
    IncidentStatus,
    ResponseActionType,
    ContainmentType,
    ActionStatus,
    WorkflowState,
)

ROLE_KEYS = {
    "SUPER_ADMIN": "test-key-super-admin",
    "ADMIN": "test-key-admin",
    "ANALYST": "test-key-analyst",
    "AUDITOR": "test-key-auditor",
    "VIEWER": "test-key-viewer",
}

ROLE_HASHES = {
    role: hashlib.sha256(key.encode("utf-8")).hexdigest()
    for role, key in ROLE_KEYS.items()
}

@pytest.fixture(autouse=True)
def clean_store():
    """Ensure the SOAR store is clean before and after each test."""
    store = get_store()
    store.reset()
    yield
    store.reset()

@pytest.fixture
def auth_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Configures environment variables for RBAC testing and returns a TestClient."""
    monkeypatch.setenv("AEGIS_ROLE_SUPER_ADMIN", ROLE_HASHES["SUPER_ADMIN"])
    monkeypatch.setenv("AEGIS_ROLE_ADMIN", ROLE_HASHES["ADMIN"])
    monkeypatch.setenv("AEGIS_ROLE_ANALYST", ROLE_HASHES["ANALYST"])
    monkeypatch.setenv("AEGIS_ROLE_AUDITOR", ROLE_HASHES["AUDITOR"])
    monkeypatch.setenv("AEGIS_ROLE_VIEWER", ROLE_HASHES["VIEWER"])
    monkeypatch.setenv("AEGIS_API_KEY_HASHES", ROLE_HASHES["SUPER_ADMIN"])

    from src.api.main import app
    return TestClient(app)


# --- Unit Tests ---

def test_incident_creation():
    """Test incident creation, status, and properties."""
    service = get_soar_service()
    
    incident = service.create_incident(
        title="Suspicious Login Activity",
        description="Multiple failed logins followed by success",
        severity=ThreatSeverity.HIGH,
        source="SIEM_ALERT",
        entities=["user_123", "ip_192.168.1.1"],
        metadata={"attack_vector": "brute_force"}
    )
    
    assert incident.incident_id.startswith("INC-")
    assert incident.status == IncidentStatus.NEW
    assert incident.severity == ThreatSeverity.HIGH
    assert "user_123" in incident.entities
    
    # Test status transitions
    updated = service.update_incident_status(incident.incident_id, IncidentStatus.INVESTIGATING)
    assert updated.status == IncidentStatus.INVESTIGATING


def test_playbook_registration_and_execution():
    """Test registering and executing a playbook against an incident."""
    service = get_soar_service()
    
    tasks = [
        {"name": "Enrich IP", "task_type": "enrich"},
        {"name": "Notify Security Channel", "task_type": "notify", "parameters": {"channel": "slack", "recipient": "#alerts"}},
    ]
    rules = {"severity": "CRITICAL"}
    
    playbook = service.register_playbook(
        name="Critical Alert Playbook",
        description="Handles critical level alerts automatically",
        version="1.0.0",
        tasks=tasks,
        rules=rules
    )
    
    assert playbook.playbook_id.startswith("PLAY-")
    assert playbook.name == "Critical Alert Playbook"
    
    # Create incident that matches the rule
    incident = service.create_incident(
        title="Critical Database Access",
        description="Access to financial records from unknown IP",
        severity=ThreatSeverity.CRITICAL,
        source="GuardDuty",
        entities=["ip_198.51.100.2"],
    )
    
    # Check that a workflow execution was automatically created
    executions = service.store.list_workflow_executions()
    assert len(executions) == 1
    assert executions[0].playbook_id == playbook.playbook_id
    assert executions[0].incident_id == incident.incident_id
    assert executions[0].state == WorkflowState.COMPLETED


def test_response_actions():
    """Test response engine execution logic."""
    service = get_soar_service()
    
    action = service.execute_action(
        action_type=ResponseActionType.LOCK_ACCOUNT,
        target_id="user_malicious",
        executed_by="admin_user",
        additional_params={"reason": "Compromised credentials"}
    )
    
    assert action.action_id.startswith("ACT-")
    assert action.action_type == ResponseActionType.LOCK_ACCOUNT
    assert action.status == ActionStatus.COMPLETED
    assert action.result["status"] == "locked"


def test_threat_correlation():
    """Test correlation engine linking multiple incidents."""
    service = get_soar_service()
    
    # Create two incidents sharing a malicious IP
    inc1 = service.create_incident("Alert A", "Desc A", ThreatSeverity.LOW, "SIEM", ["ip_1.1.1.1"])
    inc2 = service.create_incident("Alert B", "Desc B", ThreatSeverity.MEDIUM, "WAF", ["ip_1.1.1.1"])
    
    correlation = service.correlate_incidents(
        name="Shared Malicious IP Correlation",
        incident_ids=[inc1.incident_id, inc2.incident_id],
        entities=["ip_1.1.1.1"]
    )
    
    assert correlation.correlation_id.startswith("CORR-")
    assert correlation.correlation_score > 0.4
    assert len(correlation.linked_incidents) == 2


def test_containment_safeguards():
    """Test containment engine rules, whitelisting, and rate-limiting."""
    service = get_soar_service()
    
    # Whitelisting check - should raise ValueError when attempting to block admin
    with pytest.raises(ValueError) as excinfo:
        service.trigger_containment(
            containment_type=ContainmentType.ACCOUNT_SUSPEND,
            target_entity="admin",
            initiated_by="sec_operator"
        )
    assert "whitelisted" in str(excinfo.value)
    
    # Rate-limiting check - should raise RuntimeError after 5 requests in a minute
    for i in range(5):
        service.trigger_containment(
            containment_type=ContainmentType.API_BLOCK,
            target_entity=f"bad_ip_{i}",
            initiated_by="sec_operator"
        )
        
    with pytest.raises(RuntimeError) as limit_info:
        service.trigger_containment(
            containment_type=ContainmentType.API_BLOCK,
            target_entity="bad_ip_5",
            initiated_by="sec_operator"
        )
    assert "rate limit exceeded" in str(limit_info.value).lower()


# --- Integration & API Tests ---

def test_api_integration_and_rbac(auth_client: TestClient):
    """Test FastAPI integration, request validation, and RBAC controls."""
    
    # 1. Test unauthorized access (No API key)
    response = auth_client.get("/api/v1/soar/incidents")
    assert response.status_code == 401  # Unauthorized
    
    # 2. Test forbidden access (Viewer role trying to create an incident, which requires Analyst)
    viewer_headers = {"X-API-Key": ROLE_KEYS["VIEWER"]}
    inc_payload = {
        "title": "API Threat",
        "description": "Created via API tests",
        "severity": "HIGH",
        "source": "API_Client",
        "entities": ["api_entity_1"],
        "metadata": {}
    }
    response = auth_client.post("/api/v1/soar/incidents", json=inc_payload, headers=viewer_headers)
    assert response.status_code == 403  # Forbidden
    
    # 3. Create Incident with Analyst role
    analyst_headers = {"X-API-Key": ROLE_KEYS["ANALYST"]}
    response = auth_client.post("/api/v1/soar/incidents", json=inc_payload, headers=analyst_headers)
    assert response.status_code == 200
    inc_data = response.json()
    assert inc_data["title"] == "API Threat"
    incident_id = inc_data["incident_id"]
    
    # 4. GET /api/v1/soar/incidents (List Incidents)
    response = auth_client.get("/api/v1/soar/incidents", headers=viewer_headers)
    assert response.status_code == 200
    assert len(response.json()) > 0
    
    # 5. GET /api/v1/soar/incidents/{id}
    response = auth_client.get(f"/api/v1/soar/incidents/{incident_id}", headers=viewer_headers)
    assert response.status_code == 200
    assert response.json()["title"] == "API Threat"

    # 6. POST /api/v1/soar/playbooks (Register Playbook - Admin only)
    admin_headers = {"X-API-Key": ROLE_KEYS["ADMIN"]}
    playbook_payload = {
        "name": "API Playbook",
        "description": "Standard response playbook",
        "version": "1.0.0",
        "tasks": [
            {"name": "Trigger Notify", "task_type": "notify", "parameters": {"channel": "slack"}}
        ],
        "rules": {"source": "API_Client"}
    }
    # Analyst should get 403
    response = auth_client.post("/api/v1/soar/playbooks", json=playbook_payload, headers=analyst_headers)
    assert response.status_code == 403
    
    # Admin should succeed
    response = auth_client.post("/api/v1/soar/playbooks", json=playbook_payload, headers=admin_headers)
    assert response.status_code == 200
    playbook_data = response.json()
    playbook_id = playbook_data["playbook_id"]
    
    # 7. POST /api/v1/soar/playbooks/execute (Manual execute - Analyst or Admin)
    exec_payload = {
        "playbook_id": playbook_id,
        "incident_id": incident_id
    }
    response = auth_client.post("/api/v1/soar/playbooks/execute", json=exec_payload, headers=analyst_headers)
    assert response.status_code == 200
    assert response.json()["state"] in ("RUNNING", "COMPLETED")
    
    # 8. GET /api/v1/soar/workflows (List executions - Viewer+)
    response = auth_client.get("/api/v1/soar/workflows", headers=viewer_headers)
    assert response.status_code == 200
    assert len(response.json()) > 0

    # 9. POST /api/v1/soar/respond (Execute response action - Analyst+)
    resp_payload = {
        "action_type": "BLOCK_IP",
        "target_id": "198.51.100.5",
        "additional_params": {}
    }
    response = auth_client.post("/api/v1/soar/respond", json=resp_payload, headers=analyst_headers)
    assert response.status_code == 200
    assert response.json()["status"] == "COMPLETED"
    
    # 10. POST /api/v1/soar/contain (Trigger containment action - Admin only)
    contain_payload = {
        "type": "NETWORK_ISOLATE",
        "target_entity": "host_compromised_99",
        "duration_seconds": 1800
    }
    # Analyst should get 403
    response = auth_client.post("/api/v1/soar/contain", json=contain_payload, headers=analyst_headers)
    assert response.status_code == 403
    
    # Admin should succeed
    response = auth_client.post("/api/v1/soar/contain", json=contain_payload, headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["status"] == "COMPLETED"

    # 11. GET /api/v1/soar/audit (Retrieve audit logs - Auditor or Admin)
    auditor_headers = {"X-API-Key": ROLE_KEYS["AUDITOR"]}
    # Viewer should get 403
    response = auth_client.get("/api/v1/soar/audit", headers=viewer_headers)
    assert response.status_code == 403
    
    # Auditor should succeed
    response = auth_client.get("/api/v1/soar/audit", headers=auditor_headers)
    assert response.status_code == 200
    assert len(response.json()) > 0

    # 12. GET /api/v1/soar/dashboard (Get dashboard metrics - Viewer+)
    response = auth_client.get("/api/v1/soar/dashboard", headers=viewer_headers)
    assert response.status_code == 200
    db_data = response.json()
    assert db_data["total_incidents"] > 0
    assert db_data["total_audit_records"] > 0
