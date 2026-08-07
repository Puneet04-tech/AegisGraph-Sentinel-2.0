"""Tests for the Security Universe WorkflowEngine."""
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from src.security_universe.workflow_engine import WorkflowEngine
from src.security_universe.models import (
    CollaborationRecord,
    IncidentSeverity,
    Team,
    TeamType,
    UnifiedIncident,
    Workflow,
    WorkflowStatus,
)

import src.security_universe.workflow_engine as workflow_module
import src.security_universe.models as models_module

FIXED_UUID = "12345678-1234-5678-1234-567812345678"
FIXED_TS = datetime(2025, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def engine():
    return WorkflowEngine()


@pytest.fixture
def risk_team():
    return Team(
        team_id="risk-001",
        name="Risk Management",
        team_type=TeamType.RISK_MANAGEMENT,
        members=["risk1", "risk2"],
        responsibilities=["Risk assessment", "Scoring"],
        contact_email="risk@company.com",
    )


class TestTeamSeeding:
    def test_three_default_teams_seeded(self, engine):
        assert set(engine.teams.keys()) == {"soc-001", "fraud-001", "aml-001"}

    def test_default_team_fields(self, engine):
        soc = engine.teams["soc-001"]
        assert soc.name == "Security Operations Center"
        assert soc.team_type == TeamType.SOC
        assert soc.members == ["analyst1", "analyst2", "manager1"]
        assert soc.responsibilities == ["Threat monitoring", "Incident response"]
        assert soc.contact_email == "soc@company.com"

    def test_fraud_team_fields(self, engine):
        fraud = engine.teams["fraud-001"]
        assert fraud.name == "Fraud Operations"
        assert fraud.team_type == TeamType.FRAUD_OPS
        assert fraud.members == ["fraud_analyst1", "fraud_analyst2"]
        assert fraud.responsibilities == ["Fraud detection", "Transaction monitoring"]
        assert fraud.contact_email == "fraud@company.com"

    def test_aml_team_fields(self, engine):
        aml = engine.teams["aml-001"]
        assert aml.name == "AML Operations"
        assert aml.team_type == TeamType.AML_OPS
        assert aml.members == ["aml_analyst1", "aml_analyst2"]
        assert aml.responsibilities == ["AML monitoring", "SAR filing"]
        assert aml.contact_email == "aml@company.com"

    def test_default_teams_have_distinct_types(self, engine):
        types = {t.team_type for t in engine.teams.values()}
        assert types == {TeamType.SOC, TeamType.FRAUD_OPS, TeamType.AML_OPS}

    def test_event_containers_start_empty(self, engine):
        assert engine.incidents == {}
        assert engine.collaborations == {}
        assert engine.workflows == {}


class TestTeamManagement:
    def test_add_team_returns_team_id(self, engine, risk_team):
        assert engine.add_team(risk_team) == "risk-001"

    def test_add_team_stores_object(self, engine, risk_team):
        engine.add_team(risk_team)
        assert engine.teams["risk-001"] is risk_team

    def test_add_team_overwrites_existing(self, engine, risk_team):
        replacement = Team(
            team_id="risk-001",
            name="New Risk",
            team_type=TeamType.COMPLIANCE,
            members=["z"],
            responsibilities=[],
            contact_email="new@company.com",
        )
        engine.add_team(risk_team)
        engine.add_team(replacement)
        assert engine.get_team("risk-001").name == "New Risk"
        assert engine.get_team("risk-001").team_type == TeamType.COMPLIANCE

    def test_get_team_returns_matching_team(self, engine):
        team = engine.get_team("fraud-001")
        assert team is engine.teams["fraud-001"]

    def test_get_team_missing_returns_none(self, engine):
        assert engine.get_team("does-not-exist") is None

    def test_get_teams_by_type(self, engine):
        teams = engine.get_teams_by_type(TeamType.SOC)
        assert [t.team_id for t in teams] == ["soc-001"]

    def test_get_teams_by_type_no_match(self, engine):
        assert engine.get_teams_by_type(TeamType.GOVERNANCE) == []

    def test_get_teams_by_type_multiple(self, engine, risk_team):
        second_soc = Team(
            team_id="soc-002",
            name="Secondary SOC",
            team_type=TeamType.SOC,
            members=["x"],
            responsibilities=[],
            contact_email="soc2@company.com",
        )
        engine.add_team(second_soc)
        engine.add_team(risk_team)
        ids = {t.team_id for t in engine.get_teams_by_type(TeamType.SOC)}
        assert ids == {"soc-001", "soc-002"}
        assert [t.team_id for t in engine.get_teams_by_type(TeamType.RISK_MANAGEMENT)] == ["risk-001"]


class TestIncidentCreation:
    def test_create_incident_sets_fields(self, engine):
        incident = engine.create_incident(
            title="Payment fraud wave",
            description="Suspicious transactions detected",
            severity="P1_CRITICAL",
            source_teams=["SOC", "FRAUD_OPS"],
        )
        assert incident.title == "Payment fraud wave"
        assert incident.description == "Suspicious transactions detected"
        assert incident.severity == IncidentSeverity.P1_CRITICAL
        assert incident.source_teams == [TeamType.SOC, TeamType.FRAUD_OPS]
        assert incident.status == WorkflowStatus.PENDING
        assert incident.related_incidents == []

    def test_create_incident_stores_in_engine(self, engine):
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        assert engine.incidents[incident.incident_id] is incident

    def test_create_incident_assigned_defaults_to_source(self, engine):
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC", "AML_OPS"])
        assert incident.assigned_teams == [TeamType.SOC, TeamType.AML_OPS]

    def test_create_incident_explicit_assigned(self, engine):
        incident = engine.create_incident(
            "A",
            "d",
            "P2_HIGH",
            source_teams=["AML_OPS"],
            assigned_teams=["AML_OPS", "COMPLIANCE"],
        )
        assert incident.assigned_teams == [TeamType.AML_OPS, TeamType.COMPLIANCE]

    def test_create_incident_empty_assigned_falls_back_to_source(self, engine):
        incident = engine.create_incident(
            "A",
            "d",
            "P4_LOW",
            source_teams=["SOC"],
            assigned_teams=[],
        )
        assert incident.assigned_teams == [TeamType.SOC]

    def test_create_incident_empty_source_and_assigned(self, engine):
        incident = engine.create_incident("A", "d", "P3_MEDIUM", [])
        assert incident.source_teams == []
        assert incident.assigned_teams == []

    def test_create_incident_generates_unique_ids(self, engine):
        first = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        second = engine.create_incident("B", "d", "P3_MEDIUM", ["SOC"])
        assert first.incident_id != second.incident_id

    def test_create_incident_uses_uuid_source(self, engine, monkeypatch):
        monkeypatch.setattr(workflow_module, "uuid4", lambda: FIXED_UUID)
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        assert incident.incident_id == FIXED_UUID

    def test_create_incident_invalid_severity_raises(self, engine):
        with pytest.raises(ValueError):
            engine.create_incident("A", "d", "P9_MEGA", ["SOC"])

    def test_create_incident_invalid_source_team_raises(self, engine):
        with pytest.raises(ValueError):
            engine.create_incident("A", "d", "P3_MEDIUM", ["NOT_A_TEAM"])

    def test_create_incident_invalid_assigned_team_raises(self, engine):
        with pytest.raises(ValueError):
            engine.create_incident(
                "A",
                "d",
                "P3_MEDIUM",
                source_teams=["SOC"],
                assigned_teams=["BOGUS_TEAM"],
            )


class TestIncidentLinking:
    def test_link_incidents_bidirectional(self, engine):
        inc_a = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        inc_b = engine.create_incident("B", "d", "P3_MEDIUM", ["FRAUD_OPS"])
        assert engine.link_incidents(inc_a.incident_id, inc_b.incident_id) is True
        assert inc_a.related_incidents == [inc_b.incident_id]
        assert inc_b.related_incidents == [inc_a.incident_id]

    def test_link_incidents_missing_first_returns_false(self, engine):
        inc_b = engine.create_incident("B", "d", "P3_MEDIUM", ["SOC"])
        assert engine.link_incidents("ghost-1", inc_b.incident_id) is False
        assert inc_b.related_incidents == []

    def test_link_incidents_missing_second_returns_false(self, engine):
        inc_a = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        assert engine.link_incidents(inc_a.incident_id, "ghost-2") is False
        assert inc_a.related_incidents == []

    def test_link_incidents_both_missing_returns_false(self, engine):
        assert engine.link_incidents("ghost-1", "ghost-2") is False

    def test_link_incidents_accumulates_multiple(self, engine):
        inc_a = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        inc_b = engine.create_incident("B", "d", "P3_MEDIUM", ["SOC"])
        inc_c = engine.create_incident("C", "d", "P3_MEDIUM", ["SOC"])
        engine.link_incidents(inc_a.incident_id, inc_b.incident_id)
        engine.link_incidents(inc_a.incident_id, inc_c.incident_id)
        assert inc_a.related_incidents == [inc_b.incident_id, inc_c.incident_id]


class TestStatusTransitions:
    def test_update_status_changes_status(self, engine):
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        result = engine.update_incident_status(incident.incident_id, "IN_PROGRESS")
        assert result is incident
        assert incident.status == WorkflowStatus.IN_PROGRESS

    @pytest.mark.parametrize("status", [s for s in WorkflowStatus])
    def test_update_status_accepts_every_enum_value(self, engine, status):
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        engine.update_incident_status(incident.incident_id, status.value)
        assert incident.status == status

    def test_update_status_full_lifecycle_chain(self, engine):
        incident = engine.create_incident("A", "d", "P1_CRITICAL", ["SOC", "FRAUD_OPS"])
        for status in ["IN_PROGRESS", "BLOCKED", "IN_PROGRESS", "COMPLETED"]:
            engine.update_incident_status(incident.incident_id, status)
        assert incident.status == WorkflowStatus.COMPLETED

    def test_update_status_missing_incident_returns_none(self, engine):
        assert engine.update_incident_status("ghost-id", "IN_PROGRESS") is None

    def test_update_status_invalid_value_raises(self, engine):
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        with pytest.raises(ValueError):
            engine.update_incident_status(incident.incident_id, "BOGUS")

    def test_update_status_does_not_alter_other_fields(self, engine):
        incident = engine.create_incident("A", "d", "P2_HIGH", ["SOC"])
        title, severity, teams = incident.title, incident.severity, incident.assigned_teams
        engine.update_incident_status(incident.incident_id, "CANCELLED")
        assert incident.title == title
        assert incident.severity == severity
        assert incident.assigned_teams == teams

    def test_update_status_sets_aware_updated_at(self, engine, monkeypatch):
        monkeypatch.setattr(workflow_module, "datetime", _FixedDateTime)
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        incident.updated_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
        engine.update_incident_status(incident.incident_id, "COMPLETED")
        assert incident.updated_at == FIXED_TS
        assert incident.updated_at.tzinfo is not None

    def test_update_status_touches_timestamp_on_every_call(self, engine, monkeypatch):
        monkeypatch.setattr(workflow_module, "datetime", _FixedDateTime)
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        engine.update_incident_status(incident.incident_id, "IN_PROGRESS")
        first = incident.updated_at
        _FixedDateTime.now_value = datetime(2025, 3, 2, 12, 0, 0, tzinfo=timezone.utc)
        engine.update_incident_status(incident.incident_id, "COMPLETED")
        assert incident.updated_at != first


class TestCollaboration:
    def test_create_collaboration_returns_record(self, engine):
        incident = engine.create_incident("A", "d", "P2_HIGH", ["SOC", "FRAUD_OPS"])
        record = engine.create_collaboration(
            incident_id=incident.incident_id,
            from_team="SOC",
            to_team="FRAUD_OPS",
            action="Escalation",
            notes="Shared evidence bundle",
            created_by="analyst1",
        )
        assert isinstance(record, CollaborationRecord)
        assert record.incident_id == incident.incident_id
        assert record.from_team == TeamType.SOC
        assert record.to_team == TeamType.FRAUD_OPS
        assert record.action == "Escalation"
        assert record.notes == "Shared evidence bundle"
        assert record.created_by == "analyst1"

    def test_create_collaboration_stored(self, engine):
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        record = engine.create_collaboration(
            incident.incident_id, "SOC", "AML_OPS", "Info", "n", "analyst1"
        )
        assert engine.collaborations[record.record_id] is record

    def test_create_collaboration_missing_incident_returns_none(self, engine):
        record = engine.create_collaboration(
            "ghost-id", "SOC", "AML_OPS", "Info", "n", "analyst1"
        )
        assert record is None
        assert engine.collaborations == {}

    def test_create_collaboration_invalid_team_raises(self, engine):
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        with pytest.raises(ValueError):
            engine.create_collaboration(
                incident.incident_id, "SOC", "NOT_A_TEAM", "Info", "n", "analyst1"
            )

    def test_create_collaboration_unique_record_ids(self, engine):
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        first = engine.create_collaboration(
            incident.incident_id, "SOC", "FRAUD_OPS", "Open", "n1", "analyst1"
        )
        second = engine.create_collaboration(
            incident.incident_id, "FRAUD_OPS", "SOC", "Reply", "n2", "fraud_analyst1"
        )
        assert first.record_id != second.record_id

    def test_create_collaboration_uses_uuid_source(self, engine, monkeypatch):
        monkeypatch.setattr(workflow_module, "uuid4", lambda: FIXED_UUID)
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        record = engine.create_collaboration(
            incident.incident_id, "SOC", "AML_OPS", "Info", "n", "analyst1"
        )
        assert record.record_id == FIXED_UUID

    def test_get_incident_collaborations_empty(self, engine):
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        assert engine.get_incident_collaborations(incident.incident_id) == []
        assert engine.get_incident_collaborations("ghost-id") == []

    def test_get_incident_collaborations_preserves_insertion_order(self, engine):
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        first = engine.create_collaboration(
            incident.incident_id, "SOC", "FRAUD_OPS", "Open", "n1", "analyst1"
        )
        second = engine.create_collaboration(
            incident.incident_id, "FRAUD_OPS", "SOC", "Reply", "n2", "fraud_analyst1"
        )
        third = engine.create_collaboration(
            incident.incident_id, "SOC", "AML_OPS", "Close", "n3", "analyst2"
        )
        assert [c.record_id for c in engine.get_incident_collaborations(incident.incident_id)] == [
            first.record_id,
            second.record_id,
            third.record_id,
        ]

    def test_collaborations_isolated_per_incident(self, engine):
        inc_a = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        inc_b = engine.create_incident("B", "d", "P3_MEDIUM", ["SOC"])
        engine.create_collaboration(
            inc_a.incident_id, "SOC", "AML_OPS", "Info", "n", "analyst1"
        )
        assert len(engine.get_incident_collaborations(inc_a.incident_id)) == 1
        assert engine.get_incident_collaborations(inc_b.incident_id) == []

    def test_collaboration_round_trip_via_dict(self, engine):
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        record = engine.create_collaboration(
            incident.incident_id, "SOC", "FRAUD_OPS", "Handoff", "n", "analyst1"
        )
        data = record.to_dict()
        assert data["from_team"] == "SOC"
        assert data["to_team"] == "FRAUD_OPS"
        assert data["incident_id"] == incident.incident_id
        assert data["created_by"] == "analyst1"
        assert data["action"] == "Handoff"
        assert data["notes"] == "n"


class TestIncidentSummary:
    def test_summary_empty(self, engine):
        assert engine.get_incident_summary() == {
            "total_incidents": 0,
            "by_status": {},
            "by_severity": {},
            "by_team": {},
        }

    def test_summary_counts_severity_and_team(self, engine):
        engine.create_incident("A", "d", "P1_CRITICAL", ["SOC"])
        engine.create_incident("B", "d", "P1_CRITICAL", ["FRAUD_OPS"])
        engine.create_incident("C", "d", "P2_HIGH", ["AML_OPS"])
        summary = engine.get_incident_summary()
        assert summary["total_incidents"] == 3
        assert summary["by_status"] == {"PENDING": 3}
        assert summary["by_severity"] == {"P1_CRITICAL": 2, "P2_HIGH": 1}
        assert summary["by_team"] == {"SOC": 1, "FRAUD_OPS": 1, "AML_OPS": 1}

    def test_summary_counts_assigned_teams_per_incident(self, engine):
        engine.create_incident(
            "A",
            "d",
            "P2_HIGH",
            source_teams=["SOC"],
            assigned_teams=["SOC", "FRAUD_OPS", "AML_OPS"],
        )
        engine.create_incident("B", "d", "P3_MEDIUM", ["FRAUD_OPS"])
        summary = engine.get_incident_summary()
        assert summary["by_team"] == {"SOC": 1, "FRAUD_OPS": 2, "AML_OPS": 1}

    def test_summary_reflects_status_updates(self, engine):
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        engine.create_incident("B", "d", "P3_MEDIUM", ["SOC"])
        engine.update_incident_status(incident.incident_id, "COMPLETED")
        summary = engine.get_incident_summary()
        assert summary["by_status"] == {"PENDING": 1, "COMPLETED": 1}

    def test_summary_pending_ratio(self, engine):
        engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        engine.create_incident("B", "d", "P3_MEDIUM", ["SOC"])
        incident_c = engine.create_incident("C", "d", "P3_MEDIUM", ["SOC"])
        engine.update_incident_status(incident_c.incident_id, "COMPLETED")
        summary = engine.get_incident_summary()
        ratio = summary["by_status"]["PENDING"] / summary["total_incidents"]
        assert ratio == pytest.approx(2 / 3)


class TestModelSerialization:
    def test_team_to_dict(self, engine, risk_team):
        data = risk_team.to_dict()
        assert data == {
            "team_id": "risk-001",
            "name": "Risk Management",
            "team_type": "RISK_MANAGEMENT",
            "members": ["risk1", "risk2"],
            "responsibilities": ["Risk assessment", "Scoring"],
            "contact_email": "risk@company.com",
        }

    def test_incident_to_dict(self, engine):
        incident = engine.create_incident(
            "A",
            "d",
            "P1_CRITICAL",
            source_teams=["SOC"],
            assigned_teams=["SOC", "FRAUD_OPS"],
        )
        data = incident.to_dict()
        assert data["incident_id"] == incident.incident_id
        assert data["title"] == "A"
        assert data["severity"] == "P1_CRITICAL"
        assert data["source_teams"] == ["SOC"]
        assert data["assigned_teams"] == ["SOC", "FRAUD_OPS"]
        assert data["status"] == "PENDING"
        assert data["related_incidents"] == []
        assert isinstance(data["created_at"], str)
        assert isinstance(data["updated_at"], str)

    def test_workflow_to_dict(self):
        workflow = Workflow(
            workflow_id="wf-001",
            name="Cross-team response",
            description="Coordinate SOC and fraud teams",
            teams_involved=[TeamType.SOC, TeamType.FRAUD_OPS],
            steps=[{"order": 1, "name": "Triage"}, {"order": 2, "name": "Contain"}],
            status=WorkflowStatus.IN_PROGRESS,
        )
        assert workflow.to_dict() == {
            "workflow_id": "wf-001",
            "name": "Cross-team response",
            "description": "Coordinate SOC and fraud teams",
            "teams_involved": ["SOC", "FRAUD_OPS"],
            "steps": [{"order": 1, "name": "Triage"}, {"order": 2, "name": "Contain"}],
            "status": "IN_PROGRESS",
        }

    def test_unified_incident_is_dataclass(self, engine):
        incident = engine.create_incident("A", "d", "P3_MEDIUM", ["SOC"])
        assert isinstance(incident, UnifiedIncident)


class _FixedDateTime:
    now_value = FIXED_TS

    @classmethod
    def now(cls, tz=None):
        return cls.now_value
