"""Compliance control status must be evaluated, not drawn.

`generate_compliance_report` chose each SOC2 control's status with
`random.choice(["compliant", "compliant", "needs_attention"])` and reported
`findings` as `random.randint(0, 5)`, unconnected to the controls listed above
it. A control could be reported compliant on one run and needing attention on
the next with no change in the underlying system, and an attestation produced
that way asserts a compliance posture that was never assessed.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.multi_agent_soc.models import (
    AgentTask,
    AgentType,
    InvestigationResult,
    InvestigationStatus,
    ThreatIntelligenceReport,
)
from src.multi_agent_soc.reporting_agent import ReportingAgent
from src.multi_agent_soc.store import SOCStore


NOW = datetime.now(timezone.utc)


def threat(severity="high", threat_type="fraud", hours_ago=1):
    report = ThreatIntelligenceReport(
        threat_type=threat_type,
        confidence=0.8,
        severity=severity,
        description="test",
    )
    report.created_at = NOW - timedelta(hours=hours_ago)
    return report


def investigation(entity_id="ACC1", risk=0.9, status=InvestigationStatus.CLOSED, hours_ago=1):
    result = InvestigationResult(
        entity_id=entity_id,
        status=status,
        risk_score=risk,
        confidence=0.8,
    )
    result.created_at = NOW - timedelta(hours=hours_ago)
    return result


def task(started_ago=3, completed_ago=1, created_ago=4):
    item = AgentTask(
        agent_type=AgentType.INVESTIGATION,
        title="t",
        description="d",
    )
    item.created_at = NOW - timedelta(hours=created_ago)
    item.started_at = None if started_ago is None else NOW - timedelta(hours=started_ago)
    item.completed_at = None if completed_ago is None else NOW - timedelta(hours=completed_ago)
    return item


def agent(threats=(), investigations=(), tasks=()) -> ReportingAgent:
    store = SOCStore()
    for item in threats:
        store.store_threat_report(item)
    for item in investigations:
        store.store_investigation(item)
    for item in tasks:
        store.store_task(item)
    return ReportingAgent(store=store)


class TestDeterminism:
    """The defect this PR exists for."""

    def test_compliance_status_is_stable_across_runs(self):
        instance = agent(investigations=[investigation()])
        statuses = {
            tuple(c["status"] for c in instance.generate_compliance_report()["controls"])
            for _ in range(50)
        }
        assert len(statuses) == 1, f"control status still non-deterministic: {statuses}"

    def test_findings_count_is_stable_across_runs(self):
        instance = agent(investigations=[investigation(status=InvestigationStatus.NEW)])
        counts = {instance.generate_compliance_report()["findings"] for _ in range(50)}
        assert len(counts) == 1, f"findings count still non-deterministic: {counts}"


class TestComplianceControls:
    def test_unresolved_investigations_fail_the_access_control(self):
        investigations = [
            investigation(status=InvestigationStatus.NEW),
            investigation(status=InvestigationStatus.NEW),
            investigation(status=InvestigationStatus.CLOSED),
        ]
        report = agent(investigations=investigations).generate_compliance_report()
        access = next(c for c in report["controls"] if c["control_id"] == "CC6.1")
        assert access["status"] == "needs_attention"
        assert "2 of 3" in access["basis"]

    def test_resolved_investigations_pass_the_access_control(self):
        report = agent(investigations=[investigation(), investigation()]).generate_compliance_report()
        access = next(c for c in report["controls"] if c["control_id"] == "CC6.1")
        assert access["status"] == "compliant"

    def test_no_activity_is_not_assessed_rather_than_compliant(self):
        """An absence of evidence is not evidence of control effectiveness."""
        report = agent().generate_compliance_report()
        assert all(c["status"] == "not_assessed" for c in report["controls"])
        assert report["controls_assessed"] == 0

    def test_authentication_threats_fail_the_authentication_control(self):
        report = agent(threats=[threat(threat_type="credential_stuffing")]).generate_compliance_report()
        auth = next(c for c in report["controls"] if c["control_id"] == "CC6.2")
        assert auth["status"] == "needs_attention"

    def test_unrelated_threats_pass_the_authentication_control(self):
        report = agent(threats=[threat(threat_type="payment_fraud")]).generate_compliance_report()
        auth = next(c for c in report["controls"] if c["control_id"] == "CC6.2")
        assert auth["status"] == "compliant"

    def test_every_control_states_its_basis(self):
        report = agent(investigations=[investigation()]).generate_compliance_report()
        assert all(c["basis"] for c in report["controls"])


class TestComplianceFindings:
    def test_findings_count_matches_the_failing_controls(self):
        """`findings` was a random int unconnected to the controls listed."""
        investigations = [investigation(status=InvestigationStatus.NEW)]
        report = agent(
            investigations=investigations,
            threats=[threat(threat_type="credential_theft")],
        ).generate_compliance_report()
        failing = [c for c in report["controls"] if c["status"] == "needs_attention"]
        assert report["findings"] == len(failing)
        assert len(report["findings_detail"]) == len(failing)

    def test_a_clean_period_reports_no_findings(self):
        report = agent(
            investigations=[investigation()], threats=[threat(threat_type="payment_fraud")]
        ).generate_compliance_report()
        assert report["findings"] == 0
        assert report["findings_detail"] == []

    def test_recommendations_name_the_failing_controls(self):
        report = agent(
            investigations=[investigation(status=InvestigationStatus.NEW)]
        ).generate_compliance_report()
        assert any("CC6.1" in r for r in report["recommendations"])

    def test_unassessed_controls_prompt_a_coverage_recommendation(self):
        report = agent().generate_compliance_report()
        assert any("Extend monitoring coverage" in r for r in report["recommendations"])


class TestComplianceFrameworks:
    def test_a_second_framework_is_supported(self):
        report = agent(investigations=[investigation()]).generate_compliance_report(framework="PCI-DSS")
        assert [c["control_id"] for c in report["controls"]] == ["10.2", "12.10"]

    def test_an_unknown_framework_reports_no_controls_rather_than_passing(self):
        report = agent(investigations=[investigation()]).generate_compliance_report(framework="NONSENSE")
        assert report["controls"] == []
        assert report["findings"] == 0
        assert report["controls_assessed"] == 0

    def test_the_period_defaults_to_thirty_days(self):
        report = agent().generate_compliance_report()
        start = datetime.fromisoformat(report["period"]["start"])
        end = datetime.fromisoformat(report["period"]["end"])
        assert (end - start).days == 30

    def test_an_explicit_period_is_honoured(self):
        start = NOW - timedelta(days=7)
        report = agent().generate_compliance_report(period_start=start, period_end=NOW)
        assert report["period"]["start"] == start.isoformat()


