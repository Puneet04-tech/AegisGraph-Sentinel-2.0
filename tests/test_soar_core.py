import asyncio
import itertools
import uuid as uuid_module
from datetime import datetime, timezone

import pytest

import src.soar.audit as soar_audit
import src.soar.orchestrator as soar_orchestrator
import src.soar.response_engine as soar_response
import src.soar.containment_engine as soar_containment
import src.soar.investigation_engine as soar_investigation
import src.soar.correlation_engine as soar_correlation
import src.soar.enrichment_engine as soar_enrichment
import src.soar.workflow_engine as soar_workflow
import src.soar.playbook_engine as soar_playbook

from src.soar.store import SOARStore
from src.soar.service import SOARService
from src.soar.audit import SOARAuditLogger
from src.soar.response_engine import ResponseEngine
from src.soar.workflow_engine import (
    WorkflowEngine,
    TASK_PENDING,
    TASK_RUNNING,
    TASK_SUCCESS,
    TASK_FAILED,
    TASK_SKIPPED,
    TASK_ROLLED_BACK,
)
from src.soar.playbook_engine import PlaybookEngine
from src.soar.models import (
    Incident,
    IncidentStatus,
    ThreatSeverity,
    Playbook,
    Investigation,
    InvestigationStatus,
    ResponseAction,
    ResponseActionType,
    ActionStatus,
    ThreatCorrelation,
    ContainmentAction,
    ContainmentType,
    WorkflowExecution,
    WorkflowState,
    CaseEnrichment,
    AuditRecord,
)

FIXED_NOW = "2025-01-01T12:00:00+00:00"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_incident(
    incident_id="INC-TEST",
    severity=ThreatSeverity.HIGH,
    source="SIEM",
    entities=None,
) -> Incident:
    return Incident(
        incident_id=incident_id,
        title="Test Incident",
        description="Test description",
        severity=severity,
        status=IncidentStatus.NEW,
        source=source,
        created_at=now_iso(),
        updated_at=now_iso(),
        entities=entities or [],
    )


def make_playbook(playbook_id="PLAY-TEST", tasks=None, rules=None) -> Playbook:
    return Playbook(
        playbook_id=playbook_id,
        name="Test Playbook",
        description="desc",
        version="1.0.0",
        tasks=tasks or [],
        rules=rules or {},
        status="Active",
        created_at=now_iso(),
    )


def make_execution(
    execution_id="WF-TEST",
    playbook_id="PLAY-TEST",
    incident_id="INC-TEST",
) -> WorkflowExecution:
    return WorkflowExecution(
        execution_id=execution_id,
        playbook_id=playbook_id,
        incident_id=incident_id,
        state=WorkflowState.RUNNING,
        current_task_index=0,
        task_results={},
        start_time=now_iso(),
    )


def make_audit(record_id, action) -> AuditRecord:
    return AuditRecord(
        record_id=record_id,
        action=action,
        user_id="u",
        ip_address="127.0.0.1",
        timestamp=now_iso(),
        status="SUCCESS",
    )


class _FakeDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


class _FakeUUID:
    def __init__(self, value: str) -> None:
        self.hex = value


def patch_uuids(monkeypatch, start=1) -> None:
    counter = itertools.count(start)

    def fake_uuid4():
        return _FakeUUID(f"{next(counter):08X}")

    monkeypatch.setattr(uuid_module, "uuid4", fake_uuid4)


def patch_utc_now(monkeypatch) -> None:
    for mod in (
        soar_audit,
        soar_orchestrator,
        soar_response,
        soar_containment,
        soar_investigation,
        soar_correlation,
        soar_enrichment,
        soar_workflow,
        soar_playbook,
    ):
        monkeypatch.setattr(mod, "datetime", _FakeDateTime)


class _FakeContainment:
    def __init__(self, containment_id: str) -> None:
        self.containment_id = containment_id


class _RecordingContainmentEngine:
    def __init__(self) -> None:
        self.created = []
        self.releases = []

    def trigger_containment(
        self, containment_type=None, target_entity=None, initiated_by=None, duration_seconds=None
    ):
        cid = f"CNT-{len(self.created) + 1}"
        self.created.append(cid)
        return _FakeContainment(cid)

    def release_containment(self, containment_id, released_by="SYSTEM_ROLLBACK"):
        self.releases.append(containment_id)


class _FlakyContainmentEngine(_RecordingContainmentEngine):
    def release_containment(self, containment_id, released_by="SYSTEM_ROLLBACK"):
        if containment_id == "CNT-1":
            raise RuntimeError("release failed")
        super().release_containment(containment_id, released_by)


class TestSOARStore:
    def test_incident_crud(self):
        store = SOARStore()
        inc = make_incident()
        store.add_incident(inc)
        assert store.get_incident(inc.incident_id) is inc
        assert store.get_incident("INC-MISSING") is None
        assert store.list_incidents() == [inc]
        inc.status = IncidentStatus.CLOSED
        store.update_incident(inc)
        assert store.get_incident(inc.incident_id).status == IncidentStatus.CLOSED

    def test_playbook_crud(self):
        store = SOARStore()
        pb = make_playbook()
        store.add_playbook(pb)
        assert store.get_playbook(pb.playbook_id) is pb
        assert store.get_playbook("PLAY-MISSING") is None
        assert store.list_playbooks() == [pb]
        pb.name = "Renamed"
        store.add_playbook(pb)
        assert store.get_playbook(pb.playbook_id).name == "Renamed"

    def test_investigation_crud_and_lookup_by_incident(self):
        store = SOARStore()
        inv = Investigation(
            investigation_id="INV-TEST",
            incident_id="INC-TEST",
            status=InvestigationStatus.ACTIVE,
            start_time=now_iso(),
        )
        store.add_investigation(inv)
        assert store.get_investigation("INV-TEST") is inv
        assert store.get_investigation("INV-MISSING") is None
        assert store.get_investigation_by_incident("INC-TEST") is inv
        assert store.get_investigation_by_incident("INC-OTHER") is None
        assert store.list_investigations() == [inv]
        inv.analyst_notes.append("note")
        store.update_investigation(inv)
        assert store.get_investigation("INV-TEST").analyst_notes == ["note"]

    def test_response_action_crud(self):
        store = SOARStore()
        action = ResponseAction(
            action_id="ACT-TEST",
            name="Block",
            action_type=ResponseActionType.BLOCK_IP,
            target_id="x",
            executed_by="u",
            executed_at=now_iso(),
        )
        store.add_response_action(action)
        assert store.get_response_action("ACT-TEST") is action
        assert store.get_response_action("ACT-MISSING") is None
        assert store.list_response_actions() == [action]
        action.status = ActionStatus.COMPLETED
        store.update_response_action(action)
        assert store.get_response_action("ACT-TEST").status == ActionStatus.ACTIVE

    def test_correlation_crud(self):
        store = SOARStore()
        corr = ThreatCorrelation(
            correlation_id="CORR-TEST",
            name="Shared IP",
            correlation_score=0.7,
            timestamp=now_iso(),
        )
        store.add_correlation(corr)
        assert store.get_correlation("CORR-TEST") is corr
        assert store.get_correlation("CORR-MISSING") is None
        assert store.list_correlations() == [corr]

    def test_containment_action_crud(self):
        store = SOARStore()
        action = ContainmentAction(
            containment_id="CNT-TEST",
            type=ContainmentType.API_BLOCK,
            target_entity="x",
            initiated_by="u",
            timestamp=now_iso(),
        )
        store.add_containment_action(action)
        assert store.get_containment_action("CNT-TEST") is action
        assert store.get_containment_action("CNT-MISSING") is None
        assert store.list_containment_actions() == [action]
        action.duration_seconds = 60
        store.update_containment_action(action)
        assert store.get_containment_action("CNT-TEST").duration_seconds == 60

    def test_workflow_execution_crud(self):
        store = SOARStore()
        execution = make_execution()
        store.add_workflow_execution(execution)
        assert store.get_workflow_execution("WF-TEST") is execution
        assert store.get_workflow_execution("WF-MISSING") is None
        assert store.list_workflow_executions() == [execution]
        execution.state = WorkflowState.COMPLETED
        store.update_workflow_execution(execution)
        assert store.get_workflow_execution("WF-TEST").state == WorkflowState.COMPLETED

    def test_enrichment_keyed_by_entity_id(self):
        store = SOARStore()
        enrichment = CaseEnrichment(
            enrichment_id="ENR-TEST",
            entity_id="entity_1",
            updated_at=now_iso(),
        )
        store.add_enrichment(enrichment)
        assert store.get_enrichment("entity_1") is enrichment
        assert store.get_enrichment("entity_missing") is None

    def test_audit_records_append_in_order(self):
        store = SOARStore()
        store.add_audit_record(make_audit("r1", "FIRST"))
        store.add_audit_record(make_audit("r2", "SECOND"))
        store.add_audit_record(make_audit("r3", "THIRD"))
        assert [r.record_id for r in store.list_audit_records()] == ["r1", "r2", "r3"]
        assert [r.action for r in store.list_audit_records()] == ["FIRST", "SECOND", "THIRD"]

    def test_list_returns_copy(self):
        store = SOARStore()
        store.add_incident(make_incident())
        result = store.list_incidents()
        result.clear()
        assert len(store.list_incidents()) == 1

    def test_reset_clears_all_collections(self):
        store = SOARStore()
        store.add_incident(make_incident())
        store.add_playbook(make_playbook())
        store.add_investigation(Investigation(
            investigation_id="INV-R", incident_id="INC-TEST", start_time=now_iso()
        ))
        store.add_workflow_execution(make_execution())
        store.add_audit_record(make_audit("r1", "A"))
        store.reset()
        assert store.list_incidents() == []
        assert store.list_playbooks() == []
        assert store.list_investigations() == []
        assert store.list_workflow_executions() == []
        assert store.list_audit_records() == []

    def test_update_without_prior_add_inserts(self):
        store = SOARStore()
        inc = make_incident()
        store.update_incident(inc)
        assert store.get_incident(inc.incident_id) is inc

    def test_duplicate_add_overwrites(self):
        store = SOARStore()
        inc1 = make_incident()
        inc2 = make_incident()
        inc2.title = "Second"
        store.add_incident(inc1)
        store.add_incident(inc2)
        assert store.get_incident("INC-TEST") is inc2
        assert len(store.list_incidents()) == 1

    def test_missing_ids_return_none_across_collections(self):
        store = SOARStore()
        assert store.get_incident("X") is None
        assert store.get_playbook("X") is None
        assert store.get_investigation("X") is None
        assert store.get_investigation_by_incident("X") is None
        assert store.get_response_action("X") is None
        assert store.get_correlation("X") is None
        assert store.get_containment_action("X") is None
        assert store.get_workflow_execution("X") is None
        assert store.get_enrichment("X") is None

    def test_empty_store_lists_are_empty(self):
        store = SOARStore()
        assert store.list_incidents() == []
        assert store.list_playbooks() == []
        assert store.list_investigations() == []
        assert store.list_response_actions() == []
        assert store.list_correlations() == []
        assert store.list_containment_actions() == []
        assert store.list_workflow_executions() == []
        assert store.list_audit_records() == []


class TestWorkflowEngine:
    def test_task_status_constants(self):
        assert TASK_PENDING == "PENDING"
        assert TASK_RUNNING == "RUNNING"
        assert TASK_SUCCESS == "SUCCESS"
        assert TASK_FAILED == "FAILED"
        assert TASK_SKIPPED == "SKIPPED"
        assert TASK_ROLLED_BACK == "ROLLED_BACK"

    def test_workflow_state_rejects_task_level_statuses(self):
        with pytest.raises(ValueError):
            WorkflowState("ROLLED_BACK")
        with pytest.raises(ValueError):
            WorkflowState("PENDING")
        assert WorkflowState("RUNNING") == WorkflowState.RUNNING
        assert WorkflowState("COMPLETED") == WorkflowState.COMPLETED

    def test_successful_run_with_mixed_tasks(self):
        service = SOARService()
        store = service.store
        incident = make_incident(severity=ThreatSeverity.HIGH, entities=["ip_malicious_1"])
        store.add_incident(incident)
        tasks = [
            {"name": "Enrich", "task_type": "enrich"},
            {
                "name": "Contain",
                "task_type": "contain",
                "parameters": {"containment_type": "API_BLOCK", "target_entity": "bad_ip_77", "duration": 3600},
            },
            {
                "name": "Notify",
                "task_type": "notify",
                "parameters": {"channel": "slack", "recipient": "#alerts"},
            },
            {"name": "Generic", "task_type": "generic"},
        ]
        store.add_playbook(make_playbook(tasks=tasks))
        execution = make_execution()
        store.add_workflow_execution(execution)

        asyncio.run(service.workflow_engine.run_workflow(execution))

        assert execution.state == WorkflowState.COMPLETED
        assert execution.end_time is not None
        assert execution.current_task_index == 3
        assert execution.task_results["Enrich"]["status"] == TASK_SUCCESS
        assert execution.task_results["Enrich"]["enrichment_id"].startswith("ENR-")
        assert execution.task_results["Contain"]["status"] == TASK_SUCCESS
        containment_id = execution.task_results["Contain"]["containment_id"]
        assert store.get_containment_action(containment_id).target_entity == "bad_ip_77"
        assert execution.task_results["Notify"]["status"] == TASK_SUCCESS
        assert execution.task_results["Generic"]["status"] == TASK_SUCCESS
        assert execution.task_results["Generic"]["message"] == "Generic task executed"
        assert len(service.notification_engine.notification_log) == 1
        enrichment = store.get_enrichment("ip_malicious_1")
        assert enrichment.threat_intel_data["reputation_score"] == pytest.approx(0.95)
        audit_actions = [r.action for r in store.list_audit_records()]
        assert "WORKFLOW_COMPLETED" in audit_actions

    def test_run_response_task(self):
        service = SOARService()
        store = service.store
        store.add_incident(make_incident())
        tasks = [
            {
                "name": "Block",
                "task_type": "response",
                "parameters": {"action_type": "BLOCK_IP", "target_id": "198.51.100.7"},
            }
        ]
        store.add_playbook(make_playbook(tasks=tasks))
        execution = make_execution()
        store.add_workflow_execution(execution)
        asyncio.run(service.workflow_engine.run_workflow(execution))
        assert execution.state == WorkflowState.COMPLETED
        assert execution.task_results["Block"]["status"] == TASK_SUCCESS
        action = store.get_response_action(execution.task_results["Block"]["action_id"])
        assert action.status == ActionStatus.COMPLETED
        assert action.result["status"] == "blocked"

    def test_run_notify_task_records_notification(self):
        service = SOARService()
        service.store.add_incident(make_incident(incident_id="INC-N"))
        tasks = [
            {"name": "Notify", "task_type": "notify", "parameters": {"channel": "slack", "recipient": "#alerts"}}
        ]
        service.store.add_playbook(make_playbook(tasks=tasks))
        execution = make_execution(incident_id="INC-N")
        service.store.add_workflow_execution(execution)
        asyncio.run(service.workflow_engine.run_workflow(execution))
        assert execution.state == WorkflowState.COMPLETED
        assert execution.task_results["Notify"]["status"] == TASK_SUCCESS
        log = service.notification_engine.notification_log
        assert len(log) == 1
        assert log[0]["channel"] == "slack"
        assert log[0]["recipient"] == "#alerts"

    def test_enrich_without_entities_succeeds_with_message(self):
        service = SOARService()
        service.store.add_incident(make_incident(incident_id="INC-0", entities=[]))
        tasks = [{"name": "Enrich", "task_type": "enrich"}]
        service.store.add_playbook(make_playbook(tasks=tasks))
        execution = make_execution(incident_id="INC-0")
        service.store.add_workflow_execution(execution)
        asyncio.run(service.workflow_engine.run_workflow(execution))
        assert execution.state == WorkflowState.COMPLETED
        assert execution.task_results["Enrich"] == {
            "status": TASK_SUCCESS,
            "message": "No enrichment engine or entities",
        }

    def test_run_empty_playbook_completes(self):
        service = SOARService()
        service.store.add_incident(make_incident())
        service.store.add_playbook(make_playbook(tasks=[]))
        execution = make_execution()
        service.store.add_workflow_execution(execution)
        asyncio.run(service.workflow_engine.run_workflow(execution))
        assert execution.state == WorkflowState.COMPLETED
        assert execution.task_results == {}
        assert execution.end_time is not None

    def test_run_marks_failed_when_playbook_missing(self):
        service = SOARService()
        service.store.add_incident(make_incident())
        execution = make_execution()
        service.store.add_workflow_execution(execution)
        asyncio.run(service.workflow_engine.run_workflow(execution))
        assert execution.state == WorkflowState.FAILED
        assert execution.end_time is not None
        assert execution.task_results == {}

    def test_run_marks_failed_when_incident_missing(self):
        service = SOARService()
        service.store.add_playbook(make_playbook())
        execution = make_execution()
        service.store.add_workflow_execution(execution)
        asyncio.run(service.workflow_engine.run_workflow(execution))
        assert execution.state == WorkflowState.FAILED
        assert execution.end_time is not None

    def test_conditional_routing_skips_remaining_tasks(self):
        service = SOARService()
        store = service.store
        store.add_incident(make_incident(severity=ThreatSeverity.HIGH))
        tasks = [
            {"name": "Check", "task_type": "generic", "conditional_routing": {"if_severity_is": "CRITICAL"}},
            {"name": "Second", "task_type": "generic"},
            {"name": "Third", "task_type": "generic"},
        ]
        store.add_playbook(make_playbook(tasks=tasks))
        execution = make_execution()
        store.add_workflow_execution(execution)
        asyncio.run(service.workflow_engine.run_workflow(execution))
        assert execution.state == WorkflowState.COMPLETED
        assert execution.task_results["Check"]["status"] == TASK_SKIPPED
        assert execution.task_results["Check"]["message"] == "Condition not met: severity mismatch"
        assert execution.task_results["Second"]["status"] == TASK_SKIPPED
        assert execution.task_results["Second"]["message"] == "Skipped due to prior conditional routing"
        assert execution.task_results["Third"]["status"] == TASK_SKIPPED

    def test_conditional_routing_runs_when_severity_matches(self):
        service = SOARService()
        store = service.store
        store.add_incident(make_incident(severity=ThreatSeverity.CRITICAL))
        tasks = [
            {"name": "Run", "task_type": "generic", "conditional_routing": {"if_severity_is": "CRITICAL"}},
            {"name": "After", "task_type": "generic"},
        ]
        store.add_playbook(make_playbook(tasks=tasks))
        execution = make_execution()
        store.add_workflow_execution(execution)
        asyncio.run(service.workflow_engine.run_workflow(execution))
        assert execution.state == WorkflowState.COMPLETED
        assert execution.task_results["Run"]["status"] == TASK_SUCCESS
        assert execution.task_results["After"]["status"] == TASK_SUCCESS

    def test_failure_rolls_back_containments_in_reverse(self):
        store = SOARStore()
        audit = SOARAuditLogger(store)
        recorder = _RecordingContainmentEngine()
        wf = WorkflowEngine(
            store,
            audit,
            response_engine=ResponseEngine(store, audit),
            containment_engine=recorder,
        )
        store.add_incident(make_incident(incident_id="INC-RB"))
        tasks = [
            {"name": "ContainA", "task_type": "contain", "parameters": {"containment_type": "API_BLOCK", "target_entity": "a"}},
            {"name": "ContainB", "task_type": "contain", "parameters": {"containment_type": "API_BLOCK", "target_entity": "b"}},
            {"name": "Bad", "task_type": "response", "parameters": {"action_type": "BOGUS"}},
        ]
        store.add_playbook(make_playbook(tasks=tasks))
        execution = make_execution(incident_id="INC-RB")
        store.add_workflow_execution(execution)

        asyncio.run(wf.run_workflow(execution))

        assert execution.state == WorkflowState.FAILED
        assert execution.end_time is not None
        assert execution.task_results["ContainA"]["status"] == TASK_SUCCESS
        assert execution.task_results["ContainB"]["status"] == TASK_SUCCESS
        assert execution.task_results["Bad"]["status"] == TASK_FAILED
        assert "error" in execution.task_results["Bad"]
        assert recorder.releases == ["CNT-2", "CNT-1"]
        audit_actions = [r.action for r in store.list_audit_records()]
        assert "WORKFLOW_FAILED" in audit_actions
        assert "WORKFLOW_ROLLBACK_CONTAINMENT" in audit_actions

    def test_rollback_continues_when_one_release_fails(self):
        store = SOARStore()
        audit = SOARAuditLogger(store)
        flaky = _FlakyContainmentEngine()
        wf = WorkflowEngine(
            store,
            audit,
            response_engine=ResponseEngine(store, audit),
            containment_engine=flaky,
        )
        store.add_incident(make_incident(incident_id="INC-FL"))
        tasks = [
            {"name": "ContainA", "task_type": "contain", "parameters": {"containment_type": "API_BLOCK", "target_entity": "a"}},
            {"name": "ContainB", "task_type": "contain", "parameters": {"containment_type": "API_BLOCK", "target_entity": "b"}},
            {"name": "Bad", "task_type": "response", "parameters": {"action_type": "BOGUS"}},
        ]
        store.add_playbook(make_playbook(tasks=tasks))
        execution = make_execution(incident_id="INC-FL")
        store.add_workflow_execution(execution)
        asyncio.run(wf.run_workflow(execution))
        assert flaky.releases == ["CNT-2"]
        rollback_audits = [
            r for r in store.list_audit_records() if r.action == "WORKFLOW_ROLLBACK_CONTAINMENT"
        ]
        assert any(r.status == "SUCCESS" for r in rollback_audits)
        assert any(r.status == "FAILED" for r in rollback_audits)

    def test_rollback_noop_with_empty_stack(self):
        service = SOARService()
        store = service.store
        execution = make_execution()
        store.add_workflow_execution(execution)
        service.workflow_engine._rollback_containments([], execution)
        assert store.list_containment_actions() == []

    def test_rollback_noop_without_containment_engine(self):
        store = SOARStore()
        audit = SOARAuditLogger(store)
        wf = WorkflowEngine(store, audit)
        execution = make_execution()
        wf._rollback_containments(["CNT-1"], execution)
        assert store.list_containment_actions() == []
        assert store.list_audit_records() == []

    def test_run_records_aware_utc_end_time(self, monkeypatch):
        patch_utc_now(monkeypatch)
        service = SOARService()
        service.store.add_incident(make_incident())
        service.store.add_playbook(make_playbook(tasks=[{"name": "t1", "task_type": "generic"}]))
        execution = make_execution()
        service.store.add_workflow_execution(execution)
        asyncio.run(service.workflow_engine.run_workflow(execution))
        assert execution.end_time == FIXED_NOW
        parsed = datetime.fromisoformat(execution.end_time)
        assert parsed.tzinfo is not None
        assert parsed.utcoffset() is not None

    def test_missing_playbook_records_aware_utc_end_time(self, monkeypatch):
        patch_utc_now(monkeypatch)
        service = SOARService()
        service.store.add_incident(make_incident())
        execution = make_execution()
        service.store.add_workflow_execution(execution)
        asyncio.run(service.workflow_engine.run_workflow(execution))
        assert execution.state == WorkflowState.FAILED
        assert execution.end_time == FIXED_NOW


class TestPlaybookEngine:
    def test_register_playbook_stores_and_audits(self):
        service = SOARService()
        playbook = service.playbook_engine.register_playbook(
            name="Incident Response",
            description="Standard response",
            version="2.1.0",
            tasks=[{"name": "t1", "task_type": "generic"}],
            rules={"severity": "HIGH"},
        )
        assert playbook.playbook_id.startswith("PLAY-")
        assert playbook.name == "Incident Response"
        assert playbook.description == "Standard response"
        assert playbook.version == "2.1.0"
        assert playbook.status == "Active"
        assert playbook.tasks == [{"name": "t1", "task_type": "generic"}]
        assert playbook.rules == {"severity": "HIGH"}
        assert service.store.get_playbook(playbook.playbook_id) is playbook
        actions = [r.action for r in service.store.list_audit_records()]
        assert "REGISTER_PLAYBOOK" in actions

    def test_register_duplicate_names_get_distinct_ids(self, monkeypatch):
        patch_uuids(monkeypatch)
        service = SOARService()
        p1 = service.playbook_engine.register_playbook("Same", "d", "1.0.0", [{"name": "t1"}], {})
        p2 = service.playbook_engine.register_playbook("Same", "d", "1.0.0", [{"name": "t1"}], {})
        assert p1.playbook_id == "PLAY-00000001"
        assert p1.playbook_id != p2.playbook_id
        assert len(service.store.list_playbooks()) == 2

    def test_register_empty_tasks_and_rules(self):
        service = SOARService()
        playbook = service.playbook_engine.register_playbook("Empty", "d", "1.0.0", [], {})
        assert playbook.tasks == []
        assert playbook.rules == {}
        assert service.store.get_playbook(playbook.playbook_id) is playbook

    def test_execute_playbook_runs_to_completion(self):
        service = SOARService()
        incident = service.create_incident("Alert", "desc", ThreatSeverity.LOW, "SIEM")
        playbook = service.playbook_engine.register_playbook(
            "P", "d", "1.0.0", [{"name": "t1", "task_type": "generic"}], {}
        )
        execution = service.playbook_engine.execute_playbook(playbook.playbook_id, incident.incident_id)
        assert execution is not None
        assert execution.execution_id.startswith("WF-")
        assert execution.playbook_id == playbook.playbook_id
        assert execution.incident_id == incident.incident_id
        assert execution.state == WorkflowState.COMPLETED
        assert execution.task_results["t1"]["status"] == TASK_SUCCESS
        assert service.store.get_workflow_execution(execution.execution_id) is execution
        actions = [r.action for r in service.store.list_audit_records()]
        assert "START_PLAYBOOK_EXECUTION" in actions
        assert "WORKFLOW_COMPLETED" in actions

    def test_execute_playbook_missing_playbook_returns_none(self):
        service = SOARService()
        incident = service.create_incident("A", "d", ThreatSeverity.LOW, "SIEM")
        assert service.playbook_engine.execute_playbook("PLAY-NOPE", incident.incident_id) is None
        assert service.store.list_workflow_executions() == []

    def test_execute_playbook_missing_incident_returns_none(self):
        service = SOARService()
        playbook = service.playbook_engine.register_playbook("P", "d", "1.0.0", [], {})
        assert service.playbook_engine.execute_playbook(playbook.playbook_id, "INC-NOPE") is None
        assert service.store.list_workflow_executions() == []

    def test_execute_playbook_deterministic_ids_and_timestamps(self, monkeypatch):
        patch_uuids(monkeypatch)
        patch_utc_now(monkeypatch)
        store = SOARStore()
        audit = SOARAuditLogger(store)
        engine = PlaybookEngine(store, audit, workflow_engine=None)
        store.add_incident(make_incident(incident_id="INC-FIX"))
        playbook = engine.register_playbook("P", "d", "1.0.0", [{"name": "t1", "task_type": "generic"}], {})
        assert playbook.playbook_id == "PLAY-00000001"
        assert playbook.created_at == FIXED_NOW
        execution = engine.execute_playbook(playbook.playbook_id, "INC-FIX")
        assert execution.execution_id.startswith("WF-")
        assert execution.start_time == FIXED_NOW
        assert execution.state == WorkflowState.COMPLETED
        assert execution.end_time == FIXED_NOW

    def test_execute_playbook_under_running_loop_dispatches_task(self):
        store = SOARStore()
        audit = SOARAuditLogger(store)
        wf = WorkflowEngine(store, audit)
        engine = PlaybookEngine(store, audit, workflow_engine=wf)
        store.add_incident(make_incident(incident_id="INC-LP"))
        playbook = engine.register_playbook("P", "d", "1.0.0", [{"name": "t1", "task_type": "generic"}], {})

        async def scenario():
            execution = engine.execute_playbook(playbook.playbook_id, "INC-LP")
            assert execution.state == WorkflowState.RUNNING
            pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            if pending:
                await asyncio.gather(*pending)
            return execution

        execution = asyncio.run(scenario())
        assert execution.state == WorkflowState.COMPLETED
        assert execution.task_results["t1"]["status"] == TASK_SUCCESS

    def test_trigger_playbooks_by_severity_and_source(self):
        service = SOARService()
        store = service.store
        service.playbook_engine.register_playbook("Sev", "d", "1.0.0", [], {"severity": "CRITICAL"})
        service.playbook_engine.register_playbook("Src", "d", "1.0.0", [], {"source": "SIEM"})
        incident = make_incident(incident_id="INC-T1", severity=ThreatSeverity.CRITICAL, source="SIEM")
        store.add_incident(incident)
        executions = service.playbook_engine.trigger_playbooks_for_incident(incident)
        assert len(executions) == 2
        names = {store.get_playbook(e.playbook_id).name for e in executions}
        assert names == {"Sev", "Src"}

    def test_trigger_playbooks_skips_inactive_and_non_matching(self):
        service = SOARService()
        store = service.store
        inactive = service.playbook_engine.register_playbook(
            "Inactive", "d", "1.0.0", [], {"severity": "CRITICAL"}
        )
        inactive.status = "Inactive"
        store.add_playbook(inactive)
        service.playbook_engine.register_playbook("Wrong", "d", "1.0.0", [], {"severity": "LOW"})
        incident = make_incident(incident_id="INC-T2", severity=ThreatSeverity.HIGH, source="WAF")
        store.add_incident(incident)
        assert service.playbook_engine.trigger_playbooks_for_incident(incident) == []

    def test_trigger_playbooks_fallback_when_no_rules(self):
        service = SOARService()
        store = service.store
        service.playbook_engine.register_playbook("NoRules", "d", "1.0.0", [], {})
        incident = make_incident(incident_id="INC-T3")
        store.add_incident(incident)
        executions = service.playbook_engine.trigger_playbooks_for_incident(incident)
        assert len(executions) == 1
        assert store.get_playbook(executions[0].playbook_id).name == "NoRules"

    def test_trigger_playbooks_no_match_when_rules_disagree(self):
        service = SOARService()
        store = service.store
        service.playbook_engine.register_playbook("Sev", "d", "1.0.0", [], {"severity": "LOW"})
        service.playbook_engine.register_playbook("Src", "d", "1.0.0", [], {"source": "WAF"})
        incident = make_incident(incident_id="INC-T4", severity=ThreatSeverity.HIGH, source="SIEM")
        store.add_incident(incident)
        assert service.playbook_engine.trigger_playbooks_for_incident(incident) == []

    def test_trigger_playbooks_requires_severity_and_source(self):
        """Playbook with both severity and source rules requires AND match."""
        service = SOARService()
        store = service.store
        service.playbook_engine.register_playbook(
            "Both",
            "d",
            "1.0.0",
            [],
            {"severity": "CRITICAL", "source": "SIEM"},
        )
        # Severity matches, source does not -> must not trigger
        partial = make_incident(
            incident_id="INC-AND-1",
            severity=ThreatSeverity.CRITICAL,
            source="WAF",
        )
        store.add_incident(partial)
        assert service.playbook_engine.trigger_playbooks_for_incident(partial) == []

        # Source matches, severity does not -> must not trigger
        other = make_incident(
            incident_id="INC-AND-2",
            severity=ThreatSeverity.HIGH,
            source="SIEM",
        )
        store.add_incident(other)
        assert service.playbook_engine.trigger_playbooks_for_incident(other) == []

        # Both match -> trigger
        full = make_incident(
            incident_id="INC-AND-3",
            severity=ThreatSeverity.CRITICAL,
            source="SIEM",
        )
        store.add_incident(full)
        executions = service.playbook_engine.trigger_playbooks_for_incident(full)
        assert len(executions) == 1
        assert store.get_playbook(executions[0].playbook_id).name == "Both"

    def test_sync_fallback_without_workflow_engine(self):
        store = SOARStore()
        audit = SOARAuditLogger(store)
        engine = PlaybookEngine(store, audit, workflow_engine=None)
        store.add_incident(make_incident(incident_id="INC-SF", severity=ThreatSeverity.HIGH))
        playbook = engine.register_playbook(
            "Sync",
            "d",
            "1.0.0",
            [{"name": "t1", "task_type": "generic"}, {"name": "t2", "task_type": "generic"}],
            {},
        )
        execution = engine.execute_playbook(playbook.playbook_id, "INC-SF")
        assert execution.state == WorkflowState.COMPLETED
        assert execution.task_results["t1"]["message"] == "Executed successfully"
        assert execution.task_results["t2"]["message"] == "Executed successfully"
        actions = [r.action for r in store.list_audit_records()]
        assert "COMPLETE_PLAYBOOK_EXECUTION" in actions

    def test_sync_fallback_conditional_routing_breaks(self):
        store = SOARStore()
        audit = SOARAuditLogger(store)
        engine = PlaybookEngine(store, audit, workflow_engine=None)
        store.add_incident(make_incident(incident_id="INC-CB", severity=ThreatSeverity.HIGH))
        playbook = engine.register_playbook(
            "Cond",
            "d",
            "1.0.0",
            [
                {"name": "t1", "task_type": "generic", "conditional_routing": {"if_severity_is": "CRITICAL"}},
                {"name": "t2", "task_type": "generic"},
            ],
            {},
        )
        execution = engine.execute_playbook(playbook.playbook_id, "INC-CB")
        assert execution.state == WorkflowState.COMPLETED
        assert execution.task_results["t1"]["message"] == "Skipped due to condition"
        assert "t2" not in execution.task_results


class TestSOARService:
    def test_create_and_get_incident(self):
        service = SOARService()
        incident = service.create_incident(
            "Suspicious Login",
            "desc",
            ThreatSeverity.MEDIUM,
            "SIEM",
            entities=["user_1"],
            metadata={"attack_vector": "brute_force"},
        )
        assert incident.incident_id.startswith("INC-")
        assert incident.status == IncidentStatus.NEW
        assert incident.severity == ThreatSeverity.MEDIUM
        assert incident.entities == ["user_1"]
        assert incident.metadata == {"attack_vector": "brute_force"}
        assert service.get_incident(incident.incident_id) is incident
        assert service.get_incident("INC-MISSING") is None

    def test_create_incident_defaults_empty_entities_and_metadata(self):
        service = SOARService()
        incident = service.create_incident("A", "d", ThreatSeverity.LOW, "SIEM")
        assert incident.entities == []
        assert incident.metadata == {}
        assert incident.assigned_analyst is None

    def test_update_incident_status_and_missing(self):
        service = SOARService()
        incident = service.create_incident("A", "d", ThreatSeverity.LOW, "SIEM")
        updated = service.update_incident_status(incident.incident_id, IncidentStatus.INVESTIGATING, user_id="analyst_1")
        assert updated.status == IncidentStatus.INVESTIGATING
        assert updated.updated_at is not None
        assert service.update_incident_status("INC-NOPE", IncidentStatus.CLOSED) is None

    def test_register_and_list_playbooks(self):
        service = SOARService()
        p1 = service.register_playbook("P1", "d", "1.0.0", [], {"severity": "HIGH"})
        p2 = service.register_playbook("P2", "d", "2.0.0", [], {})
        assert service.get_playbook(p1.playbook_id) is p1
        assert service.get_playbook("PLAY-MISSING") is None
        assert [p.playbook_id for p in service.list_playbooks()] == [p1.playbook_id, p2.playbook_id]

    def test_execute_playbook_delegation(self):
        service = SOARService()
        incident = service.create_incident("A", "d", ThreatSeverity.LOW, "SIEM")
        playbook = service.register_playbook("P", "d", "1.0.0", [{"name": "t1", "task_type": "generic"}], {})
        execution = service.execute_playbook(playbook.playbook_id, incident.incident_id)
        assert execution is not None
        assert execution.state == WorkflowState.COMPLETED
        assert service.execute_playbook("PLAY-NOPE", incident.incident_id) is None

    def test_create_incident_auto_triggers_matching_playbook(self):
        service = SOARService()
        playbook = service.register_playbook(
            "Auto", "d", "1.0.0", [{"name": "t1", "task_type": "generic"}], {"severity": "CRITICAL"}
        )
        incident = service.create_incident("Alert", "d", ThreatSeverity.CRITICAL, "SIEM")
        executions = service.store.list_workflow_executions()
        assert len(executions) == 1
        assert executions[0].playbook_id == playbook.playbook_id
        assert executions[0].incident_id == incident.incident_id
        assert executions[0].state == WorkflowState.COMPLETED

    def test_investigation_lifecycle(self):
        service = SOARService()
        incident = service.create_incident(
            "A", "d", ThreatSeverity.MEDIUM, "SIEM", entities=["user_malicious_1"]
        )
        investigation = service.start_investigation(incident.incident_id)
        assert investigation.investigation_id.startswith("INV-")
        assert investigation.incident_id == incident.incident_id
        assert investigation.status == InvestigationStatus.COMPLETE
        assert len(investigation.evidence) == 1
        assert investigation.evidence[0]["entity_id"] == "user_malicious_1"
        assert investigation.findings[0] == "Entity user_malicious_1 matches known malicious patterns"
        assert service.get_investigation(investigation.investigation_id) is investigation
        assert service.get_investigation("INV-NOPE") is None
        assert service.start_investigation("INC-NOPE") is None

    def test_list_investigations(self):
        service = SOARService()
        inc = service.create_incident("A", "d", ThreatSeverity.LOW, "SIEM")
        service.start_investigation(inc.incident_id)
        investigations = service.list_investigations()
        assert len(investigations) == 1
        assert investigations[0].incident_id == inc.incident_id

    def test_add_analyst_note_and_missing(self):
        service = SOARService()
        inc = service.create_incident("A", "d", ThreatSeverity.LOW, "SIEM")
        inv = service.start_investigation(inc.incident_id)
        updated = service.add_analyst_note(inv.investigation_id, "Follow up required", user_id="analyst_1")
        assert updated.analyst_notes == ["Follow up required"]
        assert service.add_analyst_note("INV-NOPE", "note") is None

    def test_execute_action_requires_executor(self):
        service = SOARService()
        with pytest.raises(PermissionError):
            service.execute_action(ResponseActionType.LOCK_ACCOUNT, "x", "")

    def test_execute_action_variants(self):
        service = SOARService()
        locked = service.execute_action(ResponseActionType.LOCK_ACCOUNT, "user_x", "analyst_1")
        assert locked.status == ActionStatus.COMPLETED
        assert locked.result["status"] == "locked"
        assert locked.result["account_id"] == "user_x"
        revoked = service.execute_action(ResponseActionType.REVOKE_SESSION, "session_1", "analyst_1")
        assert revoked.result["status"] == "revoked"
        custom = service.execute_action(ResponseActionType.CUSTOM, "t", "analyst_1")
        assert custom.result["status"] == "unknown"
        assert service.store.get_response_action(custom.action_id) is custom

    def test_containment_trigger_release_and_missing(self):
        service = SOARService()
        action = service.trigger_containment(
            ContainmentType.API_BLOCK, "bad_ip_1", "sec_operator", duration_seconds=1800
        )
        assert action.containment_id.startswith("CNT-")
        assert action.status == ActionStatus.ACTIVE
        assert action.duration_seconds == 1800
        released = service.release_containment(action.containment_id, "sec_operator")
        assert released is not None
        assert released.status == ActionStatus.RELEASED
        assert released.released_at is not None
        assert service.release_containment("CNT-NOPE", "x") is None

    def test_containment_whitelist_raises(self):
        service = SOARService()
        with pytest.raises(ValueError):
            service.trigger_containment(ContainmentType.ACCOUNT_SUSPEND, "admin", "sec_operator")
        with pytest.raises(ValueError):
            service.trigger_containment(ContainmentType.API_BLOCK, "Admin", "sec_operator")
        assert service.store.list_containment_actions() == []

    def test_containment_rate_limit_raises(self, monkeypatch):
        patch_utc_now(monkeypatch)
        service = SOARService()
        for i in range(5):
            service.trigger_containment(ContainmentType.API_BLOCK, f"bad_ip_{i}", "sec_operator")
        with pytest.raises(RuntimeError):
            service.trigger_containment(ContainmentType.API_BLOCK, "bad_ip_5", "sec_operator")
        assert len(service.store.list_containment_actions()) == 5

    def test_correlation_score(self):
        service = SOARService()
        inc1 = service.create_incident("A", "d", ThreatSeverity.LOW, "SIEM", entities=["ip_1.1.1.1"])
        inc2 = service.create_incident("B", "d", ThreatSeverity.MEDIUM, "WAF", entities=["ip_1.1.1.1"])
        corr = service.correlate_incidents("Shared IP", [inc1.incident_id, inc2.incident_id], ["ip_1.1.1.1"])
        assert corr.correlation_id.startswith("CORR-")
        assert corr.correlation_score == pytest.approx(0.5)
        assert corr.matched_indicators == ["ip_1.1.1.1"]
        assert corr.linked_incidents == [inc1.incident_id, inc2.incident_id]

    def test_correlation_matched_indicators_are_unique(self):
        service = SOARService()
        inc = service.create_incident("A", "d", ThreatSeverity.LOW, "SIEM", entities=["ip_1.1.1.1"])
        corr = service.correlate_incidents("Dup", [inc.incident_id], ["ip_1.1.1.1", "ip_1.1.1.1"])
        assert corr.correlation_score == pytest.approx(0.4)
        assert corr.matched_indicators == ["ip_1.1.1.1"]

    def test_correlation_score_capped_at_one(self):
        service = SOARService()
        inc1 = service.create_incident("A", "d", ThreatSeverity.LOW, "SIEM", entities=["ip_1"])
        inc2 = service.create_incident("B", "d", ThreatSeverity.LOW, "WAF", entities=["ip_2"])
        entities = [f"entity_{i}" for i in range(5)]
        corr = service.correlate_incidents("Max", [inc1.incident_id, inc2.incident_id], entities)
        assert corr.correlation_score == pytest.approx(1.0)

    def test_list_collections(self):
        service = SOARService()
        inc = service.create_incident("A", "d", ThreatSeverity.LOW, "SIEM")
        service.execute_action(ResponseActionType.NOTIFY_ANALYST, "user_1", "analyst_1")
        service.trigger_containment(ContainmentType.API_BLOCK, "bad_ip_2", "sec_operator")
        service.correlate_incidents("C", [inc.incident_id], ["ip_1.1.1.1"])
        assert len(service.list_response_actions()) == 1
        assert len(service.list_containment_actions()) == 1
        assert len(service.list_correlations()) == 1
        assert len(service.list_audit_records()) >= 4

    def test_dashboard_active_containments_excludes_released(self):
        service = SOARService()
        active = service.trigger_containment(
            ContainmentType.API_BLOCK, "bad_ip_active", "sec_operator"
        )
        released = service.trigger_containment(
            ContainmentType.NETWORK_ISOLATE, "host_released", "sec_operator"
        )
        service.release_containment(released.containment_id, "sec_operator")
        stats = service.get_dashboard_stats()
        assert stats["active_containments"] == 1
        assert active.status == ActionStatus.ACTIVE
        assert service.store.get_containment_action(released.containment_id).status == ActionStatus.RELEASED

    def test_dashboard_stats(self):
        service = SOARService()
        inc1 = service.create_incident("A", "d", ThreatSeverity.CRITICAL, "SIEM")
        inc2 = service.create_incident("B", "d", ThreatSeverity.LOW, "WAF")
        service.update_incident_status(inc2.incident_id, IncidentStatus.CLOSED)
        service.trigger_containment(ContainmentType.NETWORK_ISOLATE, "host_99", "sec_operator")
        running = WorkflowExecution(
            execution_id="WF-RUN1",
            playbook_id="PLAY-X",
            incident_id=inc1.incident_id,
            state=WorkflowState.RUNNING,
            start_time=now_iso(),
        )
        service.store.add_workflow_execution(running)
        stats = service.get_dashboard_stats()
        assert stats["total_incidents"] == 2
        assert stats["status_distribution"] == {"NEW": 1, "INVESTIGATING": 0, "CONTAINED": 0, "CLOSED": 1}
        assert stats["severity_distribution"] == {"LOW": 1, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 1}
        assert stats["active_containments"] == 1
        assert stats["running_workflows"] == 1
        assert stats["total_audit_records"] > 0

    def test_dashboard_stats_empty(self):
        service = SOARService()
        stats = service.get_dashboard_stats()
        assert stats["total_incidents"] == 0
        assert stats["status_distribution"] == {"NEW": 0, "INVESTIGATING": 0, "CONTAINED": 0, "CLOSED": 0}
        assert stats["severity_distribution"] == {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        assert stats["active_containments"] == 0
        assert stats["running_workflows"] == 0

    def test_list_incidents_preserves_insertion_order(self):
        service = SOARService()
        ids = [service.create_incident(f"T{i}", "d", ThreatSeverity.LOW, "SIEM").incident_id for i in range(3)]
        assert [i.incident_id for i in service.list_incidents()] == ids

    def test_audit_trail_populated(self):
        service = SOARService()
        incident = service.create_incident("A", "d", ThreatSeverity.LOW, "SIEM")
        service.update_incident_status(incident.incident_id, IncidentStatus.CLOSED, user_id="analyst_9")
        actions = [r.action for r in service.list_audit_records()]
        assert "CREATE_INCIDENT" in actions
        assert "UPDATE_INCIDENT_STATUS" in actions

    def test_service_uses_provided_store(self):
        store = SOARStore()
        service = SOARService(store=store)
        assert service.store is store
        incident = service.create_incident("A", "d", ThreatSeverity.LOW, "SIEM")
        assert store.get_incident(incident.incident_id) is incident

    def test_incident_timestamps_are_aware(self):
        service = SOARService()
        incident = service.create_incident("A", "d", ThreatSeverity.LOW, "SIEM")
        parsed = datetime.fromisoformat(incident.created_at)
        assert parsed.tzinfo is not None
        assert parsed.utcoffset() is not None
