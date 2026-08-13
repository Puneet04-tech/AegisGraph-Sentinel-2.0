"""Tests that audit intelligence reports counted figures.

Risk impact, financial impact, finding age, on-track percentage, violation
trends, top violated policies and the audit activity counts were all drawn
from ``random``.
"""

import inspect
from datetime import datetime, timedelta, timezone

import pytest

from src.executive_governance import audit_intelligence as audit_intelligence_module
from src.executive_governance.audit_intelligence import AuditIntelligenceModule
from src.executive_governance.models import (
    AuditFindingSeverity,
    ComplianceStatus,
    ControlAssessment,
    PolicyViolation,
)
from src.executive_governance.store import GovernanceStore


@pytest.fixture
def store():
    return GovernanceStore()


@pytest.fixture
def audit(store):
    return AuditIntelligenceModule(store=store)


def add_violation(store, policy_name="Access Control Policy", age_days=0, status="OPEN"):
    return store.store_violation(PolicyViolation(
        policy_id="p1",
        policy_name=policy_name,
        entity_id="e1",
        entity_type="account",
        severity=AuditFindingSeverity.HIGH,
        description="violation",
        status=status,
        detected_at=datetime.now(timezone.utc) - timedelta(days=age_days),
    ))


class TestDeterminism:
    """The module must not manufacture audit figures."""

    def test_module_does_not_import_random(self):
        source = inspect.getsource(audit_intelligence_module)
        assert "import random" not in source

    def test_identical_findings_get_identical_risk_impact(self, audit):
        first = audit.create_audit_finding(
            "a", "d", AuditFindingSeverity.CRITICAL, "fraud",
        )
        second = audit.create_audit_finding(
            "b", "d", AuditFindingSeverity.CRITICAL, "fraud",
        )

        assert first.risk_impact == second.risk_impact


class TestRiskImpact:
    """Risk impact is a fixed point on the severity ladder."""

    def test_severity_orders_risk_impact(self, audit):
        impacts = [
            audit.create_audit_finding("f", "d", severity, "fraud").risk_impact
            for severity in (
                AuditFindingSeverity.INFO,
                AuditFindingSeverity.LOW,
                AuditFindingSeverity.MEDIUM,
                AuditFindingSeverity.HIGH,
                AuditFindingSeverity.CRITICAL,
            )
        ]

        assert impacts == sorted(impacts)

    def test_financial_impact_defaults_to_unknown(self, audit):
        finding = audit.create_audit_finding(
            "f", "d", AuditFindingSeverity.CRITICAL, "fraud",
        )

        assert finding.financial_impact is None

    def test_financial_impact_is_taken_from_the_caller(self, audit):
        finding = audit.create_audit_finding(
            "f", "d", AuditFindingSeverity.HIGH, "fraud", financial_impact=25000.0,
        )

        assert finding.financial_impact == 25000.0


class TestFindingSummary:
    """Age and on-track figures are measured from the findings."""

    def test_empty_store_reports_undefined_not_a_number(self, audit):
        summary = audit.get_finding_summary()

        assert summary["avg_age_days"] is None
        assert summary["on_track_percentage"] is None

    def test_average_age_measured_from_creation(self, store, audit):
        finding = audit.create_audit_finding(
            "f", "d", AuditFindingSeverity.HIGH, "fraud",
        )
        finding.created_at = datetime.now(timezone.utc) - timedelta(days=10)

        assert audit.get_finding_summary()["avg_age_days"] == pytest.approx(10, abs=0.1)

    def test_closed_findings_stop_ageing_at_closure(self, store, audit):
        finding = audit.create_audit_finding(
            "f", "d", AuditFindingSeverity.HIGH, "fraud",
        )
        finding.created_at = datetime.now(timezone.utc) - timedelta(days=30)
        finding.closed_date = datetime.now(timezone.utc) - timedelta(days=25)
        finding.status = "CLOSED"

        assert audit.get_finding_summary()["avg_age_days"] == pytest.approx(5, abs=0.1)

    def test_overdue_findings_lower_the_on_track_percentage(self, audit):
        on_time = audit.create_audit_finding(
            "a", "d", AuditFindingSeverity.HIGH, "fraud",
        )
        overdue = audit.create_audit_finding(
            "b", "d", AuditFindingSeverity.HIGH, "fraud",
        )
        overdue.due_date = datetime.now(timezone.utc) - timedelta(days=1)

        assert audit.get_finding_summary()["on_track_percentage"] == pytest.approx(50.0)
        assert on_time.due_date > datetime.now(timezone.utc)


class TestViolationTrends:
    """Violation trends are counted over the requested window."""

    def test_top_violated_policies_are_counted(self, store, audit):
        for _ in range(3):
            add_violation(store, "Access Control Policy")
        add_violation(store, "Data Protection Policy")

        trends = audit.get_violation_trends()

        assert trends["top_violated_policies"][0] == {
            "policy": "Access Control Policy", "count": 3,
        }
        assert trends["total_violations"] == 4

    def test_closed_violations_still_count_toward_trends(self, store, audit):
        add_violation(store, status="CLOSED")
        add_violation(store, status="OPEN")

        trends = audit.get_violation_trends()

        assert trends["total_violations"] == 2
        assert trends["open_violations"] == 1

    def test_days_argument_is_honoured(self, store, audit):
        add_violation(store, age_days=1)
        add_violation(store, age_days=20)

        assert audit.get_violation_trends(days=7)["total_violations"] == 1
        assert audit.get_violation_trends(days=30)["total_violations"] == 2

    def test_change_is_none_without_a_prior_window(self, store, audit):
        add_violation(store, age_days=1)

        assert audit.get_violation_trends()["trends"]["7_day_change"] is None

    def test_change_compares_against_the_prior_window(self, store, audit):
        # 2 in the prior week, 4 in the last week -> +100%.
        for _ in range(2):
            add_violation(store, age_days=10)
        for _ in range(4):
            add_violation(store, age_days=2)

        assert audit.get_violation_trends()["trends"]["7_day_change"] == pytest.approx(1.0)


class TestAuditActivity:
    """Audit counts come from control assessments and stay consistent."""

    def _add_assessment(self, store, tested_days_ago=None):
        last_tested = (
            datetime.now(timezone.utc) - timedelta(days=tested_days_ago)
            if tested_days_ago is not None else None
        )
        return store.store_assessment(ControlAssessment(
            control_id="c1",
            control_name="Control",
            framework="SOC2",
            status=ComplianceStatus.COMPLIANT,
            effectiveness_score=0.9,
            last_tested=last_tested,
        ))

    def _report(self, audit):
        now = datetime.now(timezone.utc)
        return audit.generate_audit_report(now - timedelta(days=30), now)

    def test_counts_are_internally_consistent(self, store, audit):
        self._add_assessment(store, tested_days_ago=2)
        self._add_assessment(store, tested_days_ago=5)
        self._add_assessment(store)

        summary = self._report(audit)["executive_summary"]

        assert summary["audits_completed"] == 2
        assert summary["audits_in_progress"] == 1
        assert summary["total_audits"] == 3

    def test_empty_store_reports_no_audits(self, audit):
        summary = self._report(audit)["executive_summary"]

        assert summary["total_audits"] == 0

    def test_assessments_tested_outside_the_period_are_not_completed(
        self, store, audit,
    ):
        self._add_assessment(store, tested_days_ago=200)

        summary = self._report(audit)["executive_summary"]

        assert summary["audits_completed"] == 0
