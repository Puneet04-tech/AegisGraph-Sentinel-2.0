"""
Tests for Fraud Case Management & Investigation Workflow (Phase 4).

Covers: creation, status transitions, assignment, claiming, comments,
evidence, audit timeline, pagination, and RBAC enforcement.
"""
import hashlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.api.main import app
from src.case_management import get_case_store
from src.case_management.models import CaseStatus, CasePriority

client = TestClient(app)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------
_ANALYST_KEY = "analyst-test-key-phase4"
_ANALYST_HASH = hashlib.sha256(_ANALYST_KEY.encode()).hexdigest()
_AUDITOR_KEY = "auditor-test-key-phase4"
_AUDITOR_HASH = hashlib.sha256(_AUDITOR_KEY.encode()).hexdigest()

ANA_HEADERS = {
    "Authorization": f"Bearer {_ANALYST_KEY}",
    "X-Analyst-ID": "analyst_001",
}
AUD_HEADERS = {
    "Authorization": f"Bearer {_AUDITOR_KEY}",
    "X-Analyst-ID": "auditor_001",
}


@pytest.fixture(autouse=True)
def patch_auth(monkeypatch):
    """Allow our test keys during all tests."""
    monkeypatch.setenv("AEGIS_ROLE_ANALYST", _ANALYST_HASH)
    monkeypatch.setenv("AEGIS_ROLE_AUDITOR", _AUDITOR_HASH)


@pytest.fixture()
def fresh_store():
    """Reset the singleton store between tests."""
    import src.case_management.store as _s
    old = _s._store_instance
    _s._store_instance = None
    yield get_case_store()
    _s._store_instance = old


# ---------------------------------------------------------------------------
# Unit tests – CaseStore
# ---------------------------------------------------------------------------

class TestCaseStore:
    def test_create_and_retrieve(self, fresh_store):
        store = fresh_store
        case = store.create_case("TXN_001", 0.85, "BLOCK", "analyst_001")
        assert case.case_id.startswith("CASE_")
        assert case.status == CaseStatus.OPEN
        fetched = store.get_case(case.case_id)
        assert fetched is not None
        assert fetched.transaction_id == "TXN_001"

    def test_valid_status_transition(self, fresh_store):
        store = fresh_store
        case = store.create_case("TXN_002", 0.7, "REVIEW", "analyst_001")
        store.update_status(case.case_id, CaseStatus.IN_PROGRESS, "analyst_001")
        updated = store.get_case(case.case_id)
        assert updated.status == CaseStatus.IN_PROGRESS

    def test_invalid_status_transition_raises(self, fresh_store):
        store = fresh_store
        case = store.create_case("TXN_003", 0.9, "BLOCK", "analyst_001")
        # OPEN → RESOLVED is not a valid direct transition
        with pytest.raises(ValueError, match="Invalid status transition"):
            store.update_status(case.case_id, CaseStatus.RESOLVED, "analyst_001")

    def test_closed_is_terminal(self, fresh_store):
        store = fresh_store
        case = store.create_case("TXN_004", 0.5, "ALLOW", "analyst_001")
        store.update_status(case.case_id, CaseStatus.CLOSED, "analyst_001")
        with pytest.raises(ValueError, match="terminal"):
            store.update_status(case.case_id, CaseStatus.OPEN, "analyst_001")

    def test_claim_unassigned_case(self, fresh_store):
        store = fresh_store
        case = store.create_case("TXN_005", 0.6, "REVIEW", "system")
        assert case.assigned_analyst is None
        store.claim_case(case.case_id, "analyst_002")
        updated = store.get_case(case.case_id)
        assert updated.assigned_analyst == "analyst_002"
        assert updated.status == CaseStatus.IN_PROGRESS

    def test_claim_already_assigned_raises(self, fresh_store):
        store = fresh_store
        case = store.create_case("TXN_006", 0.8, "BLOCK", "system")
        store.claim_case(case.case_id, "analyst_001")
        with pytest.raises(ValueError, match="already assigned"):
            store.claim_case(case.case_id, "analyst_002")

    def test_add_and_retrieve_comment(self, fresh_store):
        store = fresh_store
        case = store.create_case("TXN_007", 0.75, "REVIEW", "analyst_001")
        comment = store.add_comment(case.case_id, "analyst_001", "Suspicious pattern found.")
        assert comment.comment_id.startswith("CMT_")
        comments = store.get_comments(case.case_id)
        assert len(comments) == 1
        assert comments[0].text == "Suspicious pattern found."

    def test_add_evidence(self, fresh_store):
        from src.case_management.models import EvidenceType
        store = fresh_store
        case = store.create_case("TXN_008", 0.9, "BLOCK", "analyst_001")
        ev = store.add_evidence(
            case.case_id, "analyst_001", EvidenceType.TRANSACTION_LINK,
            "Linked to known mule account", reference_id="TXN_REF_001"
        )
        assert ev.evidence_id.startswith("EVD_")
        evidences = store.get_evidence(case.case_id)
        assert len(evidences) == 1

    def test_audit_trail_is_immutable(self, fresh_store):
        store = fresh_store
        case = store.create_case("TXN_009", 0.8, "BLOCK", "analyst_001")
        store.update_status(case.case_id, CaseStatus.IN_PROGRESS, "analyst_001")
        store.update_status(case.case_id, CaseStatus.ESCALATED, "analyst_001")
        timeline = store.get_timeline(case.case_id)
        # Must contain: CASE_CREATED + STATUS_CHANGED x2
        assert len(timeline) == 3
        actions = [e.action for e in timeline]
        assert "CASE_CREATED" in actions
        assert actions.count("STATUS_CHANGED") == 2
        # Modifying the returned list must not affect the store
        timeline.clear()
        assert len(store.get_timeline(case.case_id)) == 3

    def test_pagination(self, fresh_store):
        store = fresh_store
        for i in range(25):
            store.create_case(f"TXN_{i:03d}", 0.5, "REVIEW", "analyst_001")
        page1, total = store.list_cases(page=1, page_size=10)
        assert len(page1) == 10
        assert total == 25
        page3, _ = store.list_cases(page=3, page_size=10)
        assert len(page3) == 5  # 25 - 20

    def test_filter_by_status(self, fresh_store):
        store = fresh_store
        c1 = store.create_case("TXN_F1", 0.9, "BLOCK", "analyst_001")
        c2 = store.create_case("TXN_F2", 0.7, "REVIEW", "analyst_001")
        store.update_status(c2.case_id, CaseStatus.IN_PROGRESS, "analyst_001")
        results, total = store.list_cases(status=CaseStatus.OPEN)
        assert all(c.status == CaseStatus.OPEN for c in results)
        in_prog, _ = store.list_cases(status=CaseStatus.IN_PROGRESS)
        assert all(c.status == CaseStatus.IN_PROGRESS for c in in_prog)

    def test_dashboard_stats(self, fresh_store):
        store = fresh_store
        store.create_case("TXN_D1", 0.9, "BLOCK", "analyst_001", priority=CasePriority.CRITICAL)
        store.create_case("TXN_D2", 0.5, "REVIEW", "analyst_001", priority=CasePriority.LOW)
        stats = store.get_dashboard_stats()
        assert stats["total_cases"] == 2
        assert stats["open_cases"] == 2
        assert stats["by_priority"]["CRITICAL"] == 1
        assert stats["by_priority"]["LOW"] == 1


# ---------------------------------------------------------------------------
# Integration tests – API endpoints via TestClient
# ---------------------------------------------------------------------------

class TestCaseManagementAPI:
    def test_create_case_endpoint(self, fresh_store):
        resp = client.post(
            "/api/v1/cases",
            json={"transaction_id": "TXN_API_001", "risk_score": 0.85, "decision": "BLOCK", "priority": "HIGH"},
            headers=ANA_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["transaction_id"] == "TXN_API_001"
        assert data["status"] == "OPEN"
        assert data["priority"] == "HIGH"

    def test_create_case_invalid_decision(self, fresh_store):
        resp = client.post(
            "/api/v1/cases",
            json={"transaction_id": "TXN_BAD", "risk_score": 0.5, "decision": "MAYBE"},
            headers=ANA_HEADERS,
        )
        assert resp.status_code == 422

    def test_get_case_not_found(self, fresh_store):
        resp = client.get("/api/v1/cases/CASE_DOESNOTEXIST", headers=ANA_HEADERS)
        assert resp.status_code == 404

    def test_list_cases_pagination(self, fresh_store):
        for i in range(5):
            client.post(
                "/api/v1/cases",
                json={"transaction_id": f"TXN_L{i}", "risk_score": 0.5, "decision": "REVIEW"},
                headers=ANA_HEADERS,
            )
        resp = client.get("/api/v1/cases?page=1&page_size=3", headers=ANA_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["cases"]) == 3
        assert data["total"] == 5

    def test_update_case_status(self, fresh_store):
        create_resp = client.post(
            "/api/v1/cases",
            json={"transaction_id": "TXN_UPD", "risk_score": 0.8, "decision": "BLOCK"},
            headers=ANA_HEADERS,
        )
        case_id = create_resp.json()["case_id"]
        patch_resp = client.patch(
            f"/api/v1/cases/{case_id}",
            json={"status": "IN_PROGRESS"},
            headers=ANA_HEADERS,
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["status"] == "IN_PROGRESS"

    def test_update_case_invalid_transition(self, fresh_store):
        create_resp = client.post(
            "/api/v1/cases",
            json={"transaction_id": "TXN_BAD_TRN", "risk_score": 0.9, "decision": "BLOCK"},
            headers=ANA_HEADERS,
        )
        case_id = create_resp.json()["case_id"]
        patch_resp = client.patch(
            f"/api/v1/cases/{case_id}",
            json={"status": "RESOLVED"},  # OPEN → RESOLVED not allowed
            headers=ANA_HEADERS,
        )
        assert patch_resp.status_code == 422

    def test_claim_case(self, fresh_store):
        create_resp = client.post(
            "/api/v1/cases",
            json={"transaction_id": "TXN_CLAIM", "risk_score": 0.7, "decision": "REVIEW"},
            headers=ANA_HEADERS,
        )
        case_id = create_resp.json()["case_id"]
        claim_resp = client.post(f"/api/v1/cases/{case_id}/claim", headers=ANA_HEADERS)
        assert claim_resp.status_code == 200
        assert claim_resp.json()["assigned_analyst"] == "analyst_001"
        assert claim_resp.json()["status"] == "IN_PROGRESS"

    def test_add_comment(self, fresh_store):
        create_resp = client.post(
            "/api/v1/cases",
            json={"transaction_id": "TXN_CMT", "risk_score": 0.6, "decision": "REVIEW"},
            headers=ANA_HEADERS,
        )
        case_id = create_resp.json()["case_id"]
        cmt_resp = client.post(
            f"/api/v1/cases/{case_id}/comments",
            json={"text": "This is a suspicious mule transfer."},
            headers=ANA_HEADERS,
        )
        assert cmt_resp.status_code == 200
        assert cmt_resp.json()["text"] == "This is a suspicious mule transfer."
        # Evidence count should be reflected in get_case
        detail = client.get(f"/api/v1/cases/{case_id}", headers=ANA_HEADERS).json()
        assert detail["comment_count"] == 1

    def test_add_evidence(self, fresh_store):
        create_resp = client.post(
            "/api/v1/cases",
            json={"transaction_id": "TXN_EVD", "risk_score": 0.95, "decision": "BLOCK"},
            headers=ANA_HEADERS,
        )
        case_id = create_resp.json()["case_id"]
        ev_resp = client.post(
            f"/api/v1/cases/{case_id}/evidence",
            json={
                "evidence_type": "TRANSACTION_LINK",
                "description": "Linked to mule account ACC_MULE_007",
                "reference_id": "TXN_API_001",
            },
            headers=ANA_HEADERS,
        )
        assert ev_resp.status_code == 200
        assert ev_resp.json()["evidence_type"] == "TRANSACTION_LINK"
        detail = client.get(f"/api/v1/cases/{case_id}", headers=ANA_HEADERS).json()
        assert detail["evidence_count"] == 1

    def test_get_timeline(self, fresh_store):
        create_resp = client.post(
            "/api/v1/cases",
            json={"transaction_id": "TXN_TML", "risk_score": 0.85, "decision": "BLOCK"},
            headers=ANA_HEADERS,
        )
        case_id = create_resp.json()["case_id"]
        client.patch(
            f"/api/v1/cases/{case_id}",
            json={"status": "IN_PROGRESS"},
            headers=ANA_HEADERS,
        )
        tl_resp = client.get(f"/api/v1/cases/{case_id}/timeline", headers=AUD_HEADERS)
        assert tl_resp.status_code == 200
        data = tl_resp.json()
        assert data["total_events"] >= 2  # CASE_CREATED + STATUS_CHANGED
        actions = [e["action"] for e in data["events"]]
        assert "CASE_CREATED" in actions
        assert "STATUS_CHANGED" in actions

    def test_dashboard_endpoint(self, fresh_store):
        client.post(
            "/api/v1/cases",
            json={"transaction_id": "TXN_DASH", "risk_score": 0.9, "decision": "BLOCK", "priority": "CRITICAL"},
            headers=ANA_HEADERS,
        )
        resp = client.get("/api/v1/cases/dashboard", headers=ANA_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_cases" in data
        assert "by_status" in data
        assert "by_priority" in data
