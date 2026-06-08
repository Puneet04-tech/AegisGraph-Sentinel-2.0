"""Tests for the Digital Forensics & Investigation Timeline Engine (Phase 8).

This test suite is deliberately self-contained — it depends only on
case_management (Phase 4) and the forensics package itself, so that Phase 8
can be evaluated independently without requiring Phase 7 (threat_intelligence).
"""
import pytest
from fastapi.testclient import TestClient
from src.api.main import app
from src.case_management.store import get_case_store
from src.case_management.models import CasePriority
from src.forensics import (
    get_forensics_store,
    EvidenceManager,
    TimelineEngine,
    AttackReconstructionEngine,
    InvestigationService,
)

client = TestClient(app)

HEADERS = {
    "X-API-Key": "test_analyst_key",
    "X-Analyst-ID": "test_analyst_1",
}


@pytest.fixture(autouse=True)
def clean_stores():
    """Reset all in-memory stores before each test run."""
    case_store = get_case_store()
    forensics_store = get_forensics_store()

    case_store._cases.clear()
    case_store._comments.clear()
    case_store._evidence.clear()
    case_store._audit.clear()

    forensics_store._evidence.clear()
    forensics_store._investigations.clear()
    forensics_store._events.clear()
    forensics_store._chains.clear()


def test_evidence_integrity_and_tamper_detection():
    """Verify evidence hashing, verification, and tamper detection."""
    manager = EvidenceManager()

    # Register evidence
    ev = manager.register_evidence(
        case_id="case123",
        evidence_type="IP",
        source="IP_LOOKUP",
        value="103.5.5.5",
    )

    assert ev.hash is not None
    assert len(ev.hash) == 64  # SHA-256 hex length

    # Validate integrity (should succeed)
    is_valid, verified_ev = manager.verify_evidence(ev.id)
    assert is_valid is True
    assert verified_ev.value == "103.5.5.5"

    # Tamper with the evidence value in the store
    verified_ev.value = "192.168.1.1"

    # Validate integrity again (should fail)
    is_valid, _ = manager.verify_evidence(ev.id)
    assert is_valid is False


def test_timeline_engine():
    """Verify chronological timeline aggregation across cases and custom events."""
    case_store = get_case_store()
    service = InvestigationService()
    engine = TimelineEngine()

    # Create two cases
    c1 = case_store.create_case("TXN_1", 0.85, "REVIEW", "analyst1", CasePriority.HIGH)
    c2 = case_store.create_case("TXN_2", 0.95, "BLOCK", "analyst1", CasePriority.CRITICAL)

    # Link to investigation
    inv = service.create_investigation("Timeline Test", "analyst1", [c1.case_id, c2.case_id])

    # Add comments and case evidence
    case_store.add_comment(c1.case_id, "analyst1", "Suspicious device activity")

    # Register forensic evidence
    evidence_mgr = EvidenceManager()
    evidence_mgr.register_evidence(c1.case_id, "DEVICE", "FINGERPRINT", "DEV_USER_99")

    # Add custom timeline event directly to investigation
    engine.add_custom_event(
        investigation_id=inv.id,
        event_type="ANALYST_NOTE",
        entity_id=inv.id,
        description="Analyst note: confirmed threat campaign involvement.",
        metadata={"criticality": "HIGH"},
    )

    # Build timeline
    events = engine.build_timeline(inv.id)
    assert len(events) >= 5

    # Ensure chronological sorting
    for i in range(len(events) - 1):
        assert events[i].timestamp <= events[i + 1].timestamp


def test_attack_reconstruction_from_case_metadata():
    """Verify attack path reconstruction using the 'campaign:<id>' tag convention.

    Phase 8 reconstruction is self-contained: cases carry a
    ``campaign:<campaign_id>`` tag — no Phase 7 threat_intelligence needed.
    """
    case_store = get_case_store()
    engine = AttackReconstructionEngine()

    campaign_id = "CAMP_COORD_001"
    campaign_tag = f"campaign:{campaign_id}"

    # Create 3 cases tagged with the campaign
    c1 = case_store.create_case("TXN_1", 0.88, "REVIEW", "analyst1", CasePriority.HIGH, tags=[campaign_tag, "device:DEV_COORD_1"])
    c2 = case_store.create_case("TXN_2", 0.92, "BLOCK", "analyst1", CasePriority.CRITICAL, tags=[campaign_tag, "device:DEV_COORD_1"])
    c3 = case_store.create_case("TXN_3", 0.96, "BLOCK", "analyst1", CasePriority.CRITICAL, tags=[campaign_tag, "device:DEV_COORD_1"])

    # Reconstruct attack
    chain = engine.reconstruct_campaign(campaign_id)
    assert chain is not None
    assert chain.campaign_id == campaign_id
    assert len(chain.steps) == 3
    assert chain.confidence_score > 0.8
    assert chain.steps[0]["action"] == "INITIAL_COMPROMISE"
    assert chain.steps[1]["action"] == "LATERAL_PROPAGATION"
    assert chain.steps[2]["action"] == "FRAUD_CASHOUT"


def test_investigation_service_crud():
    """Verify investigation CRUD via InvestigationService."""
    service = InvestigationService()

    # Create
    inv = service.create_investigation("CRUD Test", "analyst_x", ["CASE_A", "CASE_B"])
    assert inv.title == "CRUD Test"
    assert inv.analyst_id == "analyst_x"
    assert "CASE_A" in inv.case_ids

    # List
    all_invs = service.list_investigations()
    assert any(i.id == inv.id for i in all_invs)


# ---------------------------------------------------------------------------
# API endpoint integration tests
# ---------------------------------------------------------------------------

def test_endpoints_workflow():
    """Integration test of all forensics FastAPI endpoints."""
    # 1. Create Investigation
    payload = {
        "title": "Forensics Investigation 2026",
        "case_ids": ["CASE_MOCK_01", "CASE_MOCK_02"],
    }
    response = client.post("/api/v1/forensics/investigations", json=payload, headers=HEADERS)
    assert response.status_code == 200
    inv_id = response.json()["investigation_id"]
    assert response.json()["title"] == "Forensics Investigation 2026"
    assert "CASE_MOCK_01" in response.json()["case_ids"]

    # 2. List Investigations
    response = client.get("/api/v1/forensics/investigations", headers=HEADERS)
    assert response.status_code == 200
    assert len(response.json()) >= 1

    # 3. Get Timeline
    response = client.get(f"/api/v1/forensics/timeline/{inv_id}", headers=HEADERS)
    assert response.status_code == 200
    assert response.json()["investigation_id"] == inv_id

    # 4. Register and Get / Verify Evidence
    evidence_mgr = EvidenceManager()
    ev = evidence_mgr.register_evidence("CASE_MOCK_01", "IP", "MANUAL", "10.0.0.99")

    response = client.get(f"/api/v1/forensics/evidence/{ev.id}", headers=HEADERS)
    assert response.status_code == 200
    assert response.json()["evidence_id"] == ev.id
    assert response.json()["value"] == "10.0.0.99"
    assert response.json()["hash"] == ev.hash

    # 5. Attack Reconstruction — tag a case with the campaign: tag convention
    case_store = get_case_store()
    campaign_id = "CAMP_API_TEST"
    c = case_store.create_case("TXN_Z", 0.99, "BLOCK", "analyst1", tags=[f"campaign:{campaign_id}"])

    response = client.get(f"/api/v1/forensics/reconstruction/{campaign_id}", headers=HEADERS)
    assert response.status_code == 200
    assert response.json()["campaign_id"] == campaign_id
    assert len(response.json()["steps"]) == 1
