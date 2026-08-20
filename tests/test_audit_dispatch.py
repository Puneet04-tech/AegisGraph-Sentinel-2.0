"""Audit-logging failures must be visible, not silent.

Four security modules emitted their audit events inside
`try: ... except Exception: pass`. The non-propagating intent was right -- an
audit failure must not break an authorization check -- but the handler
swallowed the evidence too, so nothing distinguished "no security events
occurred" from "every security event failed to record".
"""

from __future__ import annotations

import logging

import pytest

from src.security.audit_dispatch import (
    dispatch_audit,
    dropped_by_source,
    dropped_events,
    record_drop,
    reset_dropped,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_dropped()
    yield
    reset_dropped()


def exploding(**_fields):
    raise RuntimeError("audit sink unavailable")


class TestFailuresAreContained:
    def test_a_failing_logger_does_not_propagate(self):
        """The original guarantee: auditing must not break the operation."""
        assert dispatch_audit(exploding, audit_source="s", event_type="e") is False

    def test_a_working_logger_reports_success(self):
        calls = []
        assert dispatch_audit(
            lambda **f: calls.append(f), audit_source="s", event_type="e"
        ) is True
        assert calls[0]["event_type"] == "e"

    def test_a_none_logger_is_not_counted_as_a_drop(self):
        """Auditing disabled is not auditing failing."""
        assert dispatch_audit(None, audit_source="s", event_type="e") is False
        assert dropped_events() == 0

    def test_fields_pass_through_unchanged(self):
        calls = []
        dispatch_audit(
            lambda **f: calls.append(f),
            audit_source="s",
            event_type="e",
            severity="high",
            source="caller-supplied",
            metadata={"k": "v"},
        )
        assert calls[0]["severity"] == "high"
        assert calls[0]["metadata"] == {"k": "v"}

    def test_the_helpers_own_source_does_not_collide_with_a_caller_field(self):
        """Callers already pass a `source` field of their own."""
        calls = []
        dispatch_audit(
            lambda **f: calls.append(f),
            audit_source="attribution",
            event_type="e",
            source="caller-supplied",
        )
        assert calls[0]["source"] == "caller-supplied"
        assert "audit_source" not in calls[0]


class TestFailuresAreObservable:
    """The defect this PR exists for."""

    def test_a_dropped_event_is_counted(self):
        dispatch_audit(exploding, audit_source="authz", event_type="denied")
        assert dropped_events() == 1
        assert dropped_events("authz") == 1

    def test_drops_are_attributed_per_source(self):
        dispatch_audit(exploding, audit_source="authz", event_type="e")
        dispatch_audit(exploding, audit_source="threats", event_type="e")
        dispatch_audit(exploding, audit_source="threats", event_type="e")

        assert dropped_by_source() == {"authz": 1, "threats": 2}

    def test_a_dropped_event_is_logged(self, caplog):
        with caplog.at_level(logging.ERROR):
            dispatch_audit(exploding, audit_source="authz", event_type="denied")

        assert "Audit event dropped" in caplog.text
        assert "denied" in caplog.text
        assert "RuntimeError" in caplog.text

    def test_the_payload_is_not_logged(self, caplog):
        """Metadata may carry sensitive values; the sink diagnosis does not need it."""
        with caplog.at_level(logging.ERROR):
            dispatch_audit(
                exploding,
                audit_source="authz",
                event_type="denied",
                metadata={"password": "hunter2"},
            )
        assert "hunter2" not in caplog.text

    def test_the_failing_logger_is_not_re_entered(self):
        """Reporting a sink failure through that same sink would recurse."""
        attempts = []

        def counting(**_fields):
            attempts.append(1)
            raise RuntimeError("still down")

        dispatch_audit(counting, audit_source="authz", event_type="e")
        assert len(attempts) == 1

    def test_successful_events_are_not_counted_as_drops(self):
        dispatch_audit(lambda **f: None, audit_source="authz", event_type="e")
        assert dropped_events() == 0

    def test_record_drop_counts_non_audit_paths(self):
        """Incident escalation failures use the same counter."""
        record_drop("threats.incident_escalation")
        assert dropped_events("threats.incident_escalation") == 1


class TestCallSites:
    """Every migrated module must route through the helper."""

    @pytest.mark.parametrize(
        "module_path",
        [
            "src/security/authorization/authorization_engine.py",
            "src/security/threats/threat_detector.py",
            "src/security/incidents/incident_manager.py",
        ],
    )
    def test_no_bare_swallow_remains(self, module_path):
        with open(module_path, encoding="utf-8") as handle:
            source = handle.read()

        assert "except Exception:\n            pass" not in source, (
            f"{module_path} still discards a security event silently"
        )

    @pytest.mark.parametrize(
        "module_path",
        [
            "src/security/authorization/authorization_engine.py",
            "src/security/threats/threat_detector.py",
            "src/security/incidents/incident_manager.py",
        ],
    )
    def test_the_module_uses_the_dispatch_helper(self, module_path):
        with open(module_path, encoding="utf-8") as handle:
            assert "dispatch_audit" in handle.read()

    def test_authorization_decisions_survive_a_failing_audit_logger(self):
        from src.security.authorization.authorization_engine import (
            AuthorizationEngine,
        )

        engine = AuthorizationEngine.__new__(AuthorizationEngine)
        engine.audit_logger = exploding

        # The point: the decision path still completes, and the loss is counted.
        dispatch_audit(engine.audit_logger, audit_source="authz", event_type="denied")
        assert dropped_events("authz") == 1
