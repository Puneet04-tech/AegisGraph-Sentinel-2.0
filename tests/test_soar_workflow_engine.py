"""Workflow engine tests for the task-reported failure path (issue #3091).

A task that reports ``status == FAILED`` without raising an exception must
fail the whole workflow (rollback + FAILED + WORKFLOW_FAILED audit), not let
the execution end as COMPLETED.
"""

import asyncio
from datetime import datetime, timezone

import pytest

from src.soar.audit import SOARAuditLogger
from src.soar.models import (
    Incident,
    Playbook,
    ThreatSeverity,
    WorkflowExecution,
    WorkflowState,
)
from src.soar.store import SOARStore
from src.soar.workflow_engine import WorkflowEngine


@pytest.fixture
def store() -> SOARStore:
    s = SOARStore()
    yield s
    s.reset()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _incident(incident_id: str = "INC-WF-1") -> Incident:
    return Incident(
        incident_id=incident_id,
        title="Suspicious activity",
        description="Detection triggered",
        severity=ThreatSeverity.HIGH,
        source="SIEM",
        created_at=_now(),
        updated_at=_now(),
        entities=["user_1"],
    )


def _playbook(playbook_id: str = "PB-1") -> Playbook:
    return Playbook(
        playbook_id=playbook_id,
        name="Test Playbook",
        description="desc",
        version="1",
        tasks=[
            {"name": "notify", "task_type": "notify", "parameters": {"channel": "email"}},
        ],
        created_at=_now(),
    )


def _execution(execution_id: str = "EXEC-1", playbook_id: str = "PB-1") -> WorkflowExecution:
    return WorkflowExecution(
        execution_id=execution_id,
        playbook_id=playbook_id,
        incident_id="INC-WF-1",
        start_time=_now(),
    )


class _FailingNotifier:
    def send_notification(self, **kwargs) -> bool:
        return False


class _SucceedingNotifier:
    def send_notification(self, **kwargs) -> bool:
        return True


class _FakeContainmentAction:
    def __init__(self, containment_id: str) -> None:
        self.containment_id = containment_id


class _TrackingContainment:
    def __init__(self) -> None:
        self.released: list = []

    def trigger_containment(self, **kwargs) -> _FakeContainmentAction:
        return _FakeContainmentAction("CNT-WF-1")

    def release_containment(self, containment_id: str, released_by: str = "SYSTEM_ROLLBACK"):
        self.released.append(containment_id)
        return _FakeContainmentAction(containment_id)


def test_workflow_fails_when_task_reports_failure(store: SOARStore) -> None:
    """A task with status FAILED must end the workflow as FAILED, not COMPLETED."""
    store.add_incident(_incident())
    store.add_playbook(_playbook())

    audit_logger = SOARAuditLogger(store)
    engine = WorkflowEngine(store, audit_logger, notification_engine=_FailingNotifier())
    execution = _execution()

    asyncio.run(engine.run_workflow(execution))

    assert WorkflowState(execution.state) == WorkflowState.FAILED
    stored = store.get_workflow_execution("EXEC-1")
    assert WorkflowState(stored.state) == WorkflowState.FAILED
    assert stored.task_results["notify"]["status"] == "FAILED"
    assert [r.action for r in store.list_audit_records()] == ["WORKFLOW_FAILED"]


def test_workflow_completed_when_tasks_succeed(store: SOARStore) -> None:
    """A successful task still completes the workflow normally."""
    store.add_incident(_incident())
    store.add_playbook(_playbook())

    audit_logger = SOARAuditLogger(store)
    engine = WorkflowEngine(store, audit_logger, notification_engine=_SucceedingNotifier())
    execution = _execution()

    asyncio.run(engine.run_workflow(execution))

    assert WorkflowState(execution.state) == WorkflowState.COMPLETED
    assert [r.action for r in store.list_audit_records()] == ["WORKFLOW_COMPLETED"]


def test_workflow_rolls_back_containment_on_task_failure(store: SOARStore) -> None:
    """Containment actions are released when a later task reports failure."""
    store.add_incident(_incident())
    containment = _TrackingContainment()
    store.add_playbook(
        Playbook(
            playbook_id="PB-2",
            name="Contain then notify",
            description="desc",
            version="1",
            tasks=[
                {
                    "name": "contain",
                    "task_type": "contain",
                    "parameters": {"containment_type": "API_BLOCK", "target_entity": "user_1"},
                },
                {"name": "notify", "task_type": "notify", "parameters": {"channel": "email"}},
            ],
            created_at=_now(),
        )
    )

    audit_logger = SOARAuditLogger(store)
    engine = WorkflowEngine(
        store,
        audit_logger,
        containment_engine=containment,
        notification_engine=_FailingNotifier(),
    )
    execution = _execution(execution_id="EXEC-2", playbook_id="PB-2")

    asyncio.run(engine.run_workflow(execution))

    assert WorkflowState(execution.state) == WorkflowState.FAILED
    assert containment.released == ["CNT-WF-1"]
    actions = [r.action for r in store.list_audit_records()]
    assert "WORKFLOW_FAILED" in actions
    assert "WORKFLOW_ROLLBACK_CONTAINMENT" in actions
