import itertools
import json
import logging
import uuid as uuid_module
from datetime import datetime, timezone

import pytest

import src.soar.audit as soar_audit
import src.soar.containment_engine as soar_containment
import src.soar.correlation_engine as soar_correlation
import src.soar.enrichment_engine as soar_enrichment
import src.soar.investigation_engine as soar_investigation
import src.soar.orchestrator as soar_orchestrator
import src.soar.response_engine as soar_response

from src.soar.audit import SOARAuditLogger, json_details
from src.soar.containment_engine import ContainmentEngine
from src.soar.correlation_engine import SOARCorrelationEngine
from src.soar.enrichment_engine import EnrichmentEngine
from src.soar.investigation_engine import InvestigationEngine
from src.soar.models import (
    ActionStatus,
    ContainmentType,
    IncidentStatus,
    InvestigationStatus,
    ResponseActionType,
    ThreatSeverity,
)
from src.soar.notification_engine import NotificationEngine
from src.soar.orchestrator import IncidentOrchestrator
from src.soar.response_engine import ResponseEngine
from src.soar.store import SOARStore


@pytest.fixture
def store():
    s = SOARStore()
    yield s
    s.reset()


@pytest.fixture
def audit_logger(store):
    return SOARAuditLogger(store)


@pytest.fixture
def engines(store, audit_logger):
    return {
        "orchestrator": IncidentOrchestrator(store, audit_logger),
        "correlation": SOARCorrelationEngine(store, audit_logger),
        "investigation": InvestigationEngine(store, audit_logger),
        "containment": ContainmentEngine(store, audit_logger),
        "response": ResponseEngine(store, audit_logger),
        "enrichment": EnrichmentEngine(store, audit_logger),
        "notification": NotificationEngine(store, audit_logger),
    }


class _FakeDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2025, 3, 15, 8, 30, 0, tzinfo=timezone.utc)


class _FakeUUID:
    def __init__(self, value: str) -> None:
        self.hex = value


def patch_uuids(monkeypatch, start=1) -> None:
    counter = itertools.count(start)

    def fake_uuid4():
        return _FakeUUID(f"{next(counter):08X}")

    monkeypatch.setattr(uuid_module, "uuid4", fake_uuid4)


def patch_datetimes(monkeypatch) -> None:
    for mod in (
        soar_audit,
        soar_orchestrator,
        soar_correlation,
        soar_investigation,
        soar_containment,
        soar_response,
        soar_enrichment,
    ):
        monkeypatch.setattr(mod, "datetime", _FakeDateTime)


def test_correlate_incidents_creates_record(store, audit_logger):
    engine = SOARCorrelationEngine(store, audit_logger)
    corr = engine.correlate_incidents(
        name="Shared IP",
        incident_ids=["INC-1", "INC-2"],
        entities=["ip_1", "ip_1", "ip_2"],
    )
    assert corr.correlation_id.startswith("CORR-")
    assert corr.name == "Shared IP"
    assert sorted(corr.matched_indicators) == ["ip_1", "ip_2"]
    assert corr.linked_incidents == ["INC-1", "INC-2"]
    assert corr.correlation_score == pytest.approx(0.7)
    assert store.get_correlation(corr.correlation_id) is corr
    assert any(r.action == "CORRELATE_INCIDENTS" for r in store.list_audit_records())


def test_correlate_incidents_empty_inputs(store, audit_logger):
    engine = SOARCorrelationEngine(store, audit_logger)
    corr = engine.correlate_incidents(name="Empty", incident_ids=["INC-1"], entities=[])
    assert corr.correlation_score == pytest.approx(0.2)
    assert corr.matched_indicators == []
    assert corr.linked_incidents == ["INC-1"]


def test_correlate_incidents_score_capped(store, audit_logger):
    engine = SOARCorrelationEngine(store, audit_logger)
    corr = engine.correlate_incidents(
        name="Max",
        incident_ids=["A", "B", "C", "D", "E"],
        entities=["e1", "e2", "e3", "e4", "e5", "e6"],
    )
    assert corr.correlation_score == pytest.approx(1.0)


def test_auto_correlate_groups_shared_entities(store, audit_logger, engines):
    orch = engines["orchestrator"]
    inc1 = orch.create_incident("Alert A", "Desc A", ThreatSeverity.LOW, "SIEM", ["ip_1.1.1.1"])
    inc2 = orch.create_incident("Alert B", "Desc B", ThreatSeverity.MEDIUM, "WAF", ["ip_1.1.1.1"])
    engine = engines["correlation"]
    corrs = engine.auto_correlate_all_incidents()
    assert len(corrs) == 1
    assert corrs[0].linked_incidents == sorted([inc1.incident_id, inc2.incident_id])
    assert corrs[0].matched_indicators == ["ip_1.1.1.1"]
    assert corrs[0].name == "Auto-correlation for ip_1.1.1.1"
    assert engine.auto_correlate_all_incidents() == []


def test_auto_correlate_skips_singletons(store, audit_logger, engines):
    orch = engines["orchestrator"]
    orch.create_incident("Solo A", "Desc", ThreatSeverity.LOW, "SIEM", ["entity_a"])
    orch.create_incident("Solo B", "Desc", ThreatSeverity.LOW, "SIEM", ["entity_b"])
    corrs = engines["correlation"].auto_correlate_all_incidents()
    assert corrs == []


def test_start_investigation_missing_incident(store, audit_logger):
    engine = InvestigationEngine(store, audit_logger)
    assert engine.start_investigation("INC-NOPE") is None


def test_investigation_lifecycle(store, audit_logger):
    orch = IncidentOrchestrator(store, audit_logger)
    inc = orch.create_incident("Phish", "Desc", ThreatSeverity.HIGH, "email", ["user_malicious", "user_safe"])
    engine = InvestigationEngine(store, audit_logger)
    inv = engine.start_investigation(inc.incident_id)
    assert inv.investigation_id.startswith("INV-")
    assert inv.incident_id == inc.incident_id
    assert inv.status == InvestigationStatus.COMPLETE
    assert len(inv.evidence) == 2
    assert inv.evidence[0]["entity_id"] == "user_malicious"
    assert inv.evidence[0]["source"] == "automated_gatherer"
    assert any("matches known malicious patterns" in f for f in inv.findings)
    assert any("logged in the transaction graph" in f for f in inv.findings)
    assert inv.findings[-1] == "Automated check completed for 2 entities."
    assert store.get_investigation(inv.investigation_id) is inv
    assert store.get_investigation(inv.investigation_id).end_time is not None


def test_gather_evidence_no_entities(store, audit_logger):
    orch = IncidentOrchestrator(store, audit_logger)
    inc = orch.create_incident("Empty", "Desc", ThreatSeverity.LOW, "s", [])
    engine = InvestigationEngine(store, audit_logger)
    inv = engine.start_investigation(inc.incident_id)
    assert inv.evidence == []
    assert inv.findings == ["Automated check completed for 0 entities."]
    assert inv.status == InvestigationStatus.COMPLETE


def test_add_analyst_note(store, audit_logger):
    orch = IncidentOrchestrator(store, audit_logger)
    inc = orch.create_incident("X", "Desc", ThreatSeverity.LOW, "s", ["e1"])
    engine = InvestigationEngine(store, audit_logger)
    inv = engine.start_investigation(inc.incident_id)
    assert engine.add_analyst_note("INV-MISSING", "note") is None
    updated = engine.add_analyst_note(inv.investigation_id, "Suspicious device", user_id="analyst_1")
    assert updated.analyst_notes == ["Suspicious device"]
    assert store.get_investigation(inv.investigation_id).analyst_notes == ["Suspicious device"]
    assert any(r.action == "ADD_ANALYST_NOTE" and r.user_id == "analyst_1" for r in store.list_audit_records())


@pytest.mark.parametrize(
    "protected",
    ["sys:admin", "sys:central_switch"],
)
def test_containment_whitelist_rejected(store, audit_logger, protected):
    engine = ContainmentEngine(store, audit_logger)
    with pytest.raises(ValueError, match="whitelisted"):
        engine.trigger_containment(ContainmentType.NETWORK_ISOLATE, protected, "operator")
    assert store.list_containment_actions() == []
    assert any(r.status == "FAILED" and r.action == "BLOCK_CONTAINMENT_BYPASSED" for r in store.list_audit_records())


def test_containment_whitelist_case_insensitive(store, audit_logger):
    engine = ContainmentEngine(store, audit_logger)
    with pytest.raises(ValueError, match="whitelisted"):
        engine.trigger_containment(ContainmentType.API_BLOCK, "SYS:ADMIN", "operator")


def test_trigger_containment_success(store, audit_logger):
    engine = ContainmentEngine(store, audit_logger)
    action = engine.trigger_containment(
        ContainmentType.ACCOUNT_SUSPEND, "user_compromised", "operator", duration_seconds=3600
    )
    assert action.containment_id.startswith("CNT-")
    assert action.status == ActionStatus.ACTIVE
    assert action.type == ContainmentType.ACCOUNT_SUSPEND
    assert action.target_entity == "user_compromised"
    assert action.duration_seconds == 3600
    assert store.get_containment_action(action.containment_id) is action
    assert any(
        r.action == "TRIGGER_CONTAINMENT_ACCOUNT_SUSPEND" and r.user_id == "operator"
        for r in store.list_audit_records()
    )


def test_containment_rate_limit(store, audit_logger):
    engine = ContainmentEngine(store, audit_logger)
    for i in range(5):
        engine.trigger_containment(ContainmentType.API_BLOCK, f"bad_ip_{i}", "operator")
    with pytest.raises(RuntimeError, match="rate limit"):
        engine.trigger_containment(ContainmentType.API_BLOCK, "bad_ip_5", "operator")
    assert len(store.list_containment_actions()) == 5


def test_release_containment(store, audit_logger):
    engine = ContainmentEngine(store, audit_logger)
    assert engine.release_containment("CNT-NOPE", "operator2") is None
    action = engine.trigger_containment(ContainmentType.NETWORK_ISOLATE, "host_x", "operator")
    released = engine.release_containment(action.containment_id, "operator2")
    assert released is action
    assert released.status == ActionStatus.RELEASED
    assert released.released_at is not None
    assert any(r.action == "RELEASE_CONTAINMENT" and r.user_id == "operator2" for r in store.list_audit_records())


def test_execute_action_requires_executor(store, audit_logger):
    engine = ResponseEngine(store, audit_logger)
    with pytest.raises(PermissionError):
        engine.execute_action(ResponseActionType.LOCK_ACCOUNT, "user_x", "")


@pytest.mark.parametrize(
    "action_type,target,expected_result",
    [
        (
            ResponseActionType.LOCK_ACCOUNT,
            "user_mal",
            {"status": "locked", "account_id": "user_mal", "msg": "Account locked successfully."},
        ),
        (
            ResponseActionType.REVOKE_SESSION,
            "sess_1",
            {"status": "revoked", "session_id": "sess_1", "msg": "Session terminated."},
        ),
        (
            ResponseActionType.BLOCK_IP,
            "1.2.3.4",
            {"status": "blocked", "ip_address": "1.2.3.4", "msg": "IP added to edge blocklist."},
        ),
        (
            ResponseActionType.ESCALATE_RISK,
            "ent_9",
            {"status": "escalated", "entity_id": "ent_9", "risk_level": "CRITICAL"},
        ),
        (ResponseActionType.NOTIFY_ANALYST, "ent_1", {"status": "notified", "entity_id": "ent_1"}),
        (ResponseActionType.CUSTOM, "tgt", {"status": "unknown", "msg": "Custom action executed: CUSTOM"}),
    ],
)
def test_execute_action_variants(store, audit_logger, action_type, target, expected_result):
    engine = ResponseEngine(store, audit_logger)
    action = engine.execute_action(action_type, target, "system")
    assert action.action_id.startswith("ACT-")
    assert action.status == ActionStatus.ACTIVE
    assert action.target_id == target
    assert action.result == expected_result
    assert action.name == f"Automated {action_type.value} on {target}"
    assert store.get_response_action(action.action_id) is action
    assert any(
        r.action == f"EXECUTE_RESPONSE_ACTION_{action_type.value}" and r.status == "COMPLETED"
        for r in store.list_audit_records()
    )


def test_create_incident_defaults(store, audit_logger):
    orch = IncidentOrchestrator(store, audit_logger)
    inc = orch.create_incident("Alert", "desc", ThreatSeverity.HIGH, "SIEM")
    assert inc.incident_id.startswith("INC-")
    assert inc.status == IncidentStatus.NEW
    assert inc.severity == ThreatSeverity.HIGH
    assert inc.entities == []
    assert inc.metadata == {}
    assert store.get_incident(inc.incident_id) is inc
    assert any(r.action == "CREATE_INCIDENT" for r in store.list_audit_records())


def test_update_incident_status(store, audit_logger):
    orch = IncidentOrchestrator(store, audit_logger)
    assert orch.update_incident_status("INC-MISSING", IncidentStatus.INVESTIGATING) is None
    inc = orch.create_incident("Alert", "desc", ThreatSeverity.MEDIUM, "SIEM", ["e1"])
    updated = orch.update_incident_status(inc.incident_id, IncidentStatus.INVESTIGATING, user_id="analyst_1")
    assert updated is inc
    assert updated.status == IncidentStatus.INVESTIGATING
    assert store.get_incident(inc.incident_id).status == IncidentStatus.INVESTIGATING
    assert any(r.action == "UPDATE_INCIDENT_STATUS" and r.user_id == "analyst_1" for r in store.list_audit_records())


def test_enrich_entity_default(store, audit_logger):
    engine = EnrichmentEngine(store, audit_logger)
    enr = engine.enrich_entity("user_1")
    assert enr.enrichment_id.startswith("ENR-")
    assert enr.entity_id == "user_1"
    assert enr.resolved_entities == ["user_1"]
    assert enr.threat_intel_data["reputation_score"] == pytest.approx(0.15)
    assert enr.threat_intel_data["malicious_reports"] == 0
    assert enr.behavior_summary["average_transaction_value"] == pytest.approx(500.0)
    assert store.get_enrichment("user_1") is enr


def test_enrich_malicious_ip(store, audit_logger):
    engine = EnrichmentEngine(store, audit_logger)
    enr = engine.enrich_entity("ip_malicious_10.0.0.1")
    assert enr.threat_intel_data["reputation_score"] == pytest.approx(0.95)
    assert enr.threat_intel_data["malicious_reports"] == 14
    assert "tor_exit_node" in enr.threat_intel_data["known_associations"]
    assert enr.threat_intel_data["geo_ip_country"] == "IN"
    assert enr.threat_intel_data["isp"] == "Aegis Telecom"


def test_enrich_entity_cached(store, audit_logger):
    engine = EnrichmentEngine(store, audit_logger)
    first = engine.enrich_entity("user_1")
    second = engine.enrich_entity("user_1")
    assert second is first
    assert sum(1 for r in store.list_audit_records() if r.action == "ENRICH_ENTITY") == 1


def test_send_notification_logs(store, audit_logger):
    engine = NotificationEngine(store, audit_logger)
    ok = engine.send_notification("slack", "#alerts", "Incident opened", "details")
    assert ok is True
    assert len(engine.notification_log) == 1
    entry = engine.notification_log[0]
    assert entry["channel"] == "slack"
    assert entry["recipient"] == "#alerts"
    assert entry["subject"] == "Incident opened"
    assert entry["sent"] is True
    assert any(r.action == "SEND_NOTIFICATION_SLACK" for r in store.list_audit_records())


def test_send_notification_multiple(store, audit_logger):
    engine = NotificationEngine(store, audit_logger)
    engine.send_notification("email", "a@b.com", "subj1", "msg1")
    engine.send_notification("teams", "chan", "subj2", "msg2")
    assert len(engine.notification_log) == 2
    assert [n["subject"] for n in engine.notification_log] == ["subj1", "subj2"]
    assert all(n["sent"] for n in engine.notification_log)


def test_audit_log_action(store, audit_logger):
    record = audit_logger.log_action("TEST_ACTION", "user_1", "10.0.0.1", "SUCCESS", {"k": "v"})
    assert record.record_id.startswith("AUD-")
    assert record.action == "TEST_ACTION"
    assert record.user_id == "user_1"
    assert record.ip_address == "10.0.0.1"
    assert record.status == "SUCCESS"
    assert record.details == {"k": "v"}
    assert store.list_audit_records()[0] is record


def test_json_details_roundtrip(store, audit_logger):
    assert json.loads(json_details({"a": 1, "b": [2, 3]})) == {"a": 1, "b": [2, 3]}


def test_audit_log_action_redacts_sensitive_details(store, audit_logger, caplog):
    """The SOAR audit log line must not leak secrets from the action details."""
    with caplog.at_level(logging.INFO, logger="aegis.soar.audit"):
        record = audit_logger.log_action(
            "TEST_ACTION",
            "user_1",
            "10.0.0.1",
            "SUCCESS",
            {
                "api_key": "sk-super-secret-123",
                "nested": {"password": "p@ssword-value"},
                "user": "alice",
            },
        )

    # The stored record keeps the raw details...
    assert record.details == {
        "api_key": "sk-super-secret-123",
        "nested": {"password": "p@ssword-value"},
        "user": "alice",
    }
    # ...but the log line redacts them.
    assert "sk-super-secret-123" not in caplog.text
    assert "p@ssword-value" not in caplog.text
    assert "[REDACTED]" in caplog.text
    assert "alice" in caplog.text


def test_full_orchestration_flow(store, audit_logger, engines):
    orch = engines["orchestrator"]
    inc = orch.create_incident(
        "Suspicious transfers", "multi-hop", ThreatSeverity.CRITICAL, "AML", ["user_malicious"]
    )
    corr = engines["correlation"].correlate_incidents("AML pattern", [inc.incident_id], ["user_malicious"])
    inv = engines["investigation"].start_investigation(inc.incident_id)
    act = engines["response"].execute_action(ResponseActionType.LOCK_ACCOUNT, "user_malicious", "system")
    enr = engines["enrichment"].enrich_entity("user_malicious")
    assert inc.status == IncidentStatus.NEW
    assert corr.linked_incidents == [inc.incident_id]
    assert inv.status == InvestigationStatus.COMPLETE
    assert act.status == ActionStatus.COMPLETED
    assert enr.threat_intel_data["reputation_score"] == pytest.approx(0.95)
    assert len(store.list_audit_records()) == 6
