"""
Tests for the compliance syslog severity classification of CaseStore audit events.

Regression coverage for the severity-classification bug in ``_append_audit``:
the RFC 5424 severity was derived from the action name alone, so risk-relevant
transitions carried in ``old_value``/``new_value`` (e.g. a STATUS_CHANGED to
ESCALATED, or a CASE_CREATED for a BLOCK decision) were shipped to the
compliance server as informational (6) instead of warning (4).

RFC 5424 severity: 4 = WARNING, 6 = INFO (see SyslogClient.log_event).
"""

import pytest

from src.case_management.store import CaseStore
from src.case_management.models import (
    CasePriority,
    CaseStatus,
    EvidenceType,
)


class RecordingSyslog:
    """Fake SyslogClient that records every log_event call instead of sending UDP."""

    def __init__(self):
        self.calls = []

    def log_event(self, msg_id, message, severity=6, metadata=None):
        self.calls.append(
            {
                "msg_id": msg_id,
                "message": message,
                "severity": severity,
                "metadata": dict(metadata or {}),
            }
        )
        return True


@pytest.fixture
def store():
    store = CaseStore()
    store.syslog_client = RecordingSyslog()
    return store


def severity_of(store, index=-1):
    """Return the RFC 5424 severity recorded at *index* in the call log."""
    return store.syslog_client.calls[index]["severity"]


def call_of(store, index=-1):
    """Return the raw recorded call at *index*."""
    return store.syslog_client.calls[index]


class TestEscalationSeverity:
    """Escalations must be reported as WARNING (4), not INFO (6)."""

    def test_open_to_escalated_is_warning(self, store):
        case = store.create_case("TXN-1", 0.9, "BLOCK", "a1")
        store.update_status(case.case_id, CaseStatus.ESCALATED, "a1")

        assert severity_of(store) == 4

    def test_in_progress_to_escalated_is_warning(self, store):
        case = store.create_case("TXN-1", 0.9, "BLOCK", "a1")
        store.update_status(case.case_id, CaseStatus.IN_PROGRESS, "a1")
        store.update_status(case.case_id, CaseStatus.ESCALATED, "a1")

        assert severity_of(store) == 4

    def test_routine_transition_stays_info(self, store):
        case = store.create_case("TXN-1", 0.9, "BLOCK", "a1")
        store.update_status(case.case_id, CaseStatus.IN_PROGRESS, "a1")

        assert severity_of(store) == 6

    def test_resolution_stays_info(self, store):
        case = store.create_case("TXN-1", 0.9, "BLOCK", "a1")
        store.update_status(case.case_id, CaseStatus.IN_PROGRESS, "a1")
        store.update_status(case.case_id, CaseStatus.RESOLVED, "a1")

        assert severity_of(store) == 6

    def test_close_after_escalation_is_warning(self, store):
        case = store.create_case("TXN-1", 0.9, "BLOCK", "a1")
        store.update_status(case.case_id, CaseStatus.ESCALATED, "a1")
        store.update_status(case.case_id, CaseStatus.CLOSED, "a1")

        assert severity_of(store) == 4

    def test_escalation_event_keeps_audit_values(self, store):
        case = store.create_case("TXN-1", 0.9, "BLOCK", "a1")
        store.update_status(case.case_id, CaseStatus.ESCALATED, "a1")

        call = call_of(store)
        assert call["metadata"]["old_value"] == "OPEN"
        assert call["metadata"]["new_value"] == "ESCALATED"
        assert call["metadata"]["action"] == "STATUS_CHANGED"


class TestBlockedDecisionSeverity:
    """Cases created for BLOCK decisions must be reported as WARNING (4)."""

    def test_create_case_block_is_warning(self, store):
        store.create_case("TXN-1", 0.95, "BLOCK", "a1")

        assert severity_of(store) == 4

    def test_create_case_allow_is_info(self, store):
        store.create_case("TXN-1", 0.1, "ALLOW", "a1")

        assert severity_of(store) == 6

    def test_create_case_review_is_info(self, store):
        store.create_case("TXN-1", 0.6, "REVIEW", "a1")

        assert severity_of(store) == 6

    def test_high_priority_creation_is_info(self, store):
        store.create_case(
            "TXN-1",
            0.8,
            "REVIEW",
            "a1",
            priority=CasePriority.CRITICAL,
        )

        assert severity_of(store) == 6


class TestRoutineAuditSeverity:
    """Routine analyst actions must remain informational (6)."""

    def test_assignment_is_info(self, store):
        case = store.create_case("TXN-1", 0.6, "REVIEW", "a1")
        store.assign_analyst(case.case_id, "a2", "a1")

        assert severity_of(store) == 6

    def test_claim_is_info(self, store):
        case = store.create_case("TXN-1", 0.6, "REVIEW", "a1")
        store.claim_case(case.case_id, "a3")

        assert severity_of(store) == 6

    def test_priority_change_is_info(self, store):
        case = store.create_case("TXN-1", 0.6, "REVIEW", "a1")
        store.update_priority(case.case_id, CasePriority.HIGH, "a1")

        assert severity_of(store) == 6

    def test_comment_is_info(self, store):
        case = store.create_case("TXN-1", 0.6, "REVIEW", "a1")
        store.add_comment(case.case_id, "a1", "Following up on pattern")

        assert severity_of(store) == 6

    def test_evidence_is_info(self, store):
        case = store.create_case("TXN-1", 0.6, "REVIEW", "a1")
        store.add_evidence(
            case.case_id,
            "a1",
            EvidenceType.TRANSACTION_LINK,
            "Linked to mule cluster",
            reference_id="TXN-2",
        )

        assert severity_of(store) == 6


class TestSyslogCallShape:
    """The metadata payload sent to the compliance server must be complete."""

    def test_metadata_contains_all_fields(self, store):
        case = store.create_case("TXN-1", 0.6, "REVIEW", "a1")

        call = call_of(store)
        assert call["msg_id"] == "CASE_CREATED"
        assert call["message"] == f"Case {case.case_id} audit event by analyst a1"
        assert call["metadata"]["case_id"] == case.case_id
        assert call["metadata"]["analyst_id"] == "a1"
        assert call["metadata"]["action"] == "CASE_CREATED"
        assert call["metadata"]["old_value"] == ""
        assert "decision=REVIEW" in call["metadata"]["new_value"]

    def test_every_event_is_logged(self, store):
        case = store.create_case("TXN-1", 0.6, "REVIEW", "a1")
        store.update_status(case.case_id, CaseStatus.IN_PROGRESS, "a1")
        store.update_priority(case.case_id, CasePriority.HIGH, "a1")
        store.add_comment(case.case_id, "a1", "noted")

        assert len(store.syslog_client.calls) == 4


class TestSyslogFailureHandling:
    """A failing syslog client must never break the audit pipeline."""

    def test_log_event_failure_is_swallowed(self, store):
        def boom(*args, **kwargs):
            raise ConnectionError("compliance server down")

        store.syslog_client.log_event = boom

        case = store.create_case("TXN-1", 0.95, "BLOCK", "a1")
        store.update_status(case.case_id, CaseStatus.ESCALATED, "a1")

        # No exception propagates; in-memory audit trail is intact.
        timeline = store.get_timeline(case.case_id)
        assert [e.action for e in timeline] == ["CASE_CREATED", "STATUS_CHANGED"]

    def test_timeline_unaffected_by_severity_logic(self, store):
        case = store.create_case("TXN-1", 0.95, "BLOCK", "a1")
        store.update_status(case.case_id, CaseStatus.IN_PROGRESS, "a1")

        timeline = store.get_timeline(case.case_id)
        assert timeline[0].action == "CASE_CREATED"
        assert timeline[1].action == "STATUS_CHANGED"
        assert timeline[1].old_value == "OPEN"
        assert timeline[1].new_value == "IN_PROGRESS"
