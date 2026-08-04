"""Unit tests for the case workflow state-machine engine.

Covers ``src.case_workflow.workflow_engine.WorkflowEngine``: workflow
definitions, transition validation, case lifecycle, assignment,
escalation, SLA tracking and dashboard statistics.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from src.case_workflow.models import CaseStatus, Priority, SLALevel
from src.case_workflow.workflow_engine import WorkflowEngine


@pytest.fixture
def engine() -> WorkflowEngine:
    return WorkflowEngine()


@pytest.fixture
def standard_case(engine: WorkflowEngine):
    return engine.create_case("Fraud case", "desc", "wf-standard")


# ---------------------------------------------------------------------------
# Default workflows
# ---------------------------------------------------------------------------


class TestDefaultWorkflows:
    def test_two_default_workflows_registered(self, engine):
        assert set(engine.workflows.keys()) == {"wf-standard", "wf-incident"}

    def test_standard_workflow_initial_state(self, engine):
        assert engine.workflows["wf-standard"].initial_state == "NEW"

    def test_standard_workflow_transitions(self, engine):
        transitions = engine.workflows["wf-standard"].transitions
        assert transitions["NEW"] == ["ASSIGNED"]
        assert transitions["IN_PROGRESS"] == ["PENDING_APPROVAL", "RESOLVED", "ESCALATED"]
        assert transitions["CLOSED"] == []


# ---------------------------------------------------------------------------
# Workflow creation and transitions
# ---------------------------------------------------------------------------


class TestWorkflowCreation:
    def test_create_workflow_seeds_empty_transitions(self, engine):
        workflow = engine.create_workflow(
            "Custom", "desc", ["A", "B", "C"], initial_state="A"
        )

        assert workflow.initial_state == "A"
        assert workflow.transitions == {"A": [], "B": [], "C": []}
        assert workflow.workflow_id in engine.workflows

    def test_add_transition_validates_state_and_target(self, engine):
        workflow = engine.create_workflow("W", "d", ["A", "B"], "A")

        assert engine.add_transition(workflow.workflow_id, "A", "B") is True
        assert engine.add_transition(workflow.workflow_id, "A", "NOPE") is False
        assert engine.add_transition(workflow.workflow_id, "NOPE", "B") is False
        assert engine.add_transition("missing", "A", "B") is False

    def test_add_transition_does_not_duplicate(self, engine):
        workflow = engine.create_workflow("W", "d", ["A", "B"], "A")
        engine.add_transition(workflow.workflow_id, "A", "B")

        assert engine.add_transition(workflow.workflow_id, "A", "B") is True
        assert engine.workflows[workflow.workflow_id].transitions["A"] == ["B"]

    def test_can_transition_respects_transition_map(self, engine):
        assert engine.can_transition("wf-standard", "NEW", "ASSIGNED") is True
        assert engine.can_transition("wf-standard", "NEW", "RESOLVED") is False
        assert engine.can_transition("missing", "NEW", "ASSIGNED") is False


# ---------------------------------------------------------------------------
# Case lifecycle
# ---------------------------------------------------------------------------


class TestCaseLifecycle:
    def test_create_case_unknown_workflow_raises(self, engine):
        with pytest.raises(ValueError):
            engine.create_case("t", "d", "missing-workflow")

    def test_create_case_seeds_initial_state(self, engine, standard_case):
        assert standard_case.current_state == "NEW"
        assert standard_case.status == CaseStatus.NEW
        assert standard_case.priority == Priority.MEDIUM
        assert standard_case.workflow_id == "wf-standard"

    def test_create_case_parses_priority(self, engine):
        case = engine.create_case("t", "d", "wf-standard", priority="HIGH")
        assert case.priority == Priority.HIGH

    def test_transition_case_valid(self, engine, standard_case):
        result = engine.transition_case(standard_case.case_id, "ASSIGNED")

        assert result is standard_case
        assert standard_case.current_state == "ASSIGNED"
        assert standard_case.status == CaseStatus.ASSIGNED

    def test_transition_case_invalid_returns_none(self, engine, standard_case):
        assert engine.transition_case(standard_case.case_id, "RESOLVED") is None
        assert standard_case.current_state == "NEW"

    def test_transition_case_unknown_case_returns_none(self, engine):
        assert engine.transition_case("missing", "ASSIGNED") is None

    def test_get_cases_by_assignee(self, engine):
        a = engine.create_case("A", "d", "wf-standard", assignee="alice")
        engine.create_case("B", "d", "wf-standard", assignee="bob")

        assert engine.get_cases_by_assignee("alice") == [a]

    def test_assign_case_creates_assignment_record(self, engine, standard_case):
        assignment = engine.assign_case(standard_case.case_id, "alice", "manager")

        assert assignment is not None
        assert assignment.case_id == standard_case.case_id
        assert assignment.assignee == "alice"
        assert standard_case.assignee == "alice"
        assert engine.assign_case("missing", "alice", "manager") is None


# ---------------------------------------------------------------------------
# Escalation
# ---------------------------------------------------------------------------


class TestEscalation:
    def test_escalate_case_creates_record(self, engine, standard_case):
        escalation = engine.escalate_case(standard_case.case_id, "manager", "risk")

        assert escalation.case_id == standard_case.case_id
        assert escalation.from_assignee == "UNASSIGNED"
        assert escalation.to_assignee == "manager"
        assert escalation.reason == "risk"
        assert standard_case.current_state == "ESCALATED"
        assert standard_case.status == CaseStatus.ESCALATED
        assert standard_case.escalated_to == "manager"

    def test_escalate_case_unknown_returns_none(self, engine):
        assert engine.escalate_case("missing", "manager", "risk") is None


# ---------------------------------------------------------------------------
# SLA tracking
# ---------------------------------------------------------------------------


class TestSLA:
    def test_create_sla_sets_level_and_due_window(self, engine, standard_case):
        sla = engine.create_sla(standard_case.case_id, "P1")

        assert sla.sla_level == SLALevel.P1
        assert sla.case_id == standard_case.case_id
        assert sla.breached is False

    def test_create_sla_unknown_case_returns_none(self, engine):
        assert engine.create_sla("missing", "P1") is None

    def test_create_sla_p4_level(self, engine, standard_case):
        sla = engine.create_sla(standard_case.case_id, "P4")
        assert sla.sla_level == SLALevel.P4

    def test_check_sla_breach_when_due_passed(self, engine, standard_case):
        sla = engine.create_sla(standard_case.case_id, "P1")
        sla.due_at = sla.due_at - timedelta(hours=2)

        assert engine.check_sla_breach(sla.sla_id) is True
        assert sla.breached is True
        assert sla.breached_at is not None

    def test_check_sla_breach_not_yet_due(self, engine, standard_case):
        sla = engine.create_sla(standard_case.case_id, "P1")

        assert engine.check_sla_breach(sla.sla_id) is False

    def test_check_sla_breach_is_idempotent(self, engine, standard_case):
        sla = engine.create_sla(standard_case.case_id, "P1")
        sla.due_at = sla.due_at - timedelta(hours=2)
        engine.check_sla_breach(sla.sla_id)

        assert engine.check_sla_breach(sla.sla_id) is True

    def test_check_sla_breach_unknown_returns_false(self, engine):
        assert engine.check_sla_breach("missing") is False

    def test_get_breached_slas_aggregates(self, engine, standard_case):
        breached = engine.create_sla(standard_case.case_id, "P1")
        breached.due_at = breached.due_at - timedelta(hours=2)
        not_breached = engine.create_sla(standard_case.case_id, "P2")

        breached_slas = engine.get_breached_slas()

        assert breached.sla_id in [s.sla_id for s in breached_slas]
        assert not_breached.sla_id not in [s.sla_id for s in breached_slas]


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


class TestDashboard:
    def test_get_dashboard_counts(self, engine):
        engine.create_case("A", "d", "wf-standard", priority="HIGH")
        engine.create_case("B", "d", "wf-standard", priority="MEDIUM")

        dashboard = engine.get_dashboard()

        assert dashboard["total_cases"] == 2
        assert dashboard["total_workflows"] == 2
        assert dashboard["cases_by_status"]["NEW"] == 2
        assert dashboard["cases_by_priority"]["HIGH"] == 1
        assert dashboard["cases_by_priority"]["MEDIUM"] == 1
        assert dashboard["breached_slas"] == 0
