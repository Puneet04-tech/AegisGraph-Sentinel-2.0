"""Dedicated unit tests for src/observability/audit_logger.py.

``AuditLogger`` emits domain-specific audit events (fraud decisions, security
actions, exception traces, admin actions) as structured logs but had no direct
unit coverage.  These tests pin the emitted event types and metadata payloads
via an injected recording logger.
"""

import pytest

from src.observability.audit_logger import AuditLogger


class _RecordingLogger:
    def __init__(self) -> None:
        self.calls: list = []

    def audit(self, message, event_type="audit", metadata=None) -> None:
        self.calls.append((message, event_type, metadata))


@pytest.fixture
def logger() -> AuditLogger:
    audit = AuditLogger("audit-test")
    audit._logger = _RecordingLogger()
    return audit


def test_log_fraud_decision_payload(logger):
    logger.log_fraud_decision(
        transaction_id="txn-1",
        decision="block",
        risk_score=0.87,
        triggered_modules=["anomaly"],
    )
    _, event_type, metadata = logger._logger.calls[0]
    assert event_type == "fraud_decision"
    assert metadata["transaction_id"] == "txn-1"
    assert metadata["decision"] == "block"
    assert metadata["risk_score"] == 0.87
    assert metadata["triggered_modules"] == ["anomaly"]


def test_log_security_action_payload(logger):
    logger.log_security_action("user_suspended", actor="admin-1")
    _, event_type, metadata = logger._logger.calls[0]
    assert event_type == "security_action"
    assert metadata["action"] == "user_suspended"
    assert metadata["actor"] == "admin-1"


def test_log_exception_trace_payload(logger):
    logger.log_exception_trace(exc_type="ValueError", message="boom", status_code=500)
    message, event_type, metadata = logger._logger.calls[0]
    assert message == "boom"
    assert event_type == "exception_trace"
    assert metadata["exc_type"] == "ValueError"
    assert metadata["status_code"] == 500


def test_log_admin_action_injects_scope(logger):
    logger.log_admin_action("purge_cache")
    _, event_type, metadata = logger._logger.calls[0]
    assert event_type == "security_action"
    assert metadata["scope"] == "admin"
    assert metadata["action"] == "purge_cache"
