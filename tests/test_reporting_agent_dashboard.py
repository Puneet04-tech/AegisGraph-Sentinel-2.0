"""Executive dashboard figures must be counted, not drawn.

`generate_executive_dashboard` drew every figure it reported from `random`:
alert volume, high-risk entity count, trend deltas, task throughput, response
time and the whole severity breakdown. The dashboard therefore reported a
different security posture on each refresh, and the severity buckets never
summed to the alert total sitting above them.
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

    def test_the_dashboard_is_stable_across_refreshes(self):
        instance = agent(threats=[threat(), threat("critical")])
        seen = set()
        for _ in range(50):
            data = instance.generate_executive_dashboard()
            seen.add((
                data["overview"]["total_alerts_today"],
                data["overview"]["high_risk_entities"],
                tuple(sorted(data["alerts_by_severity"].items())),
            ))
        assert len(seen) == 1, f"dashboard still non-deterministic: {seen}"

    def test_the_module_no_longer_imports_random(self):
        import src.multi_agent_soc.reporting_agent as module

        assert not hasattr(module, "random")


class TestDashboardOverview:
    def test_alert_count_is_the_real_count(self):
        data = agent(threats=[threat(), threat(), threat()]).generate_executive_dashboard()
        assert data["overview"]["total_alerts_today"] == 3

    def test_alerts_outside_the_window_are_excluded(self):
        data = agent(threats=[threat(hours_ago=1), threat(hours_ago=40)]).generate_executive_dashboard()
        assert data["overview"]["total_alerts_today"] == 1

    def test_high_risk_entities_are_counted_distinctly(self):
        """One entity investigated three times is one entity at risk."""
        data = agent(
            investigations=[
                investigation("ACC1", 0.9),
                investigation("ACC1", 0.95),
                investigation("ACC2", 0.85),
            ]
        ).generate_executive_dashboard()
        assert data["overview"]["high_risk_entities"] == 2

    def test_low_risk_entities_are_not_counted(self):
        data = agent(
            investigations=[investigation("ACC1", 0.2), investigation("ACC2", 0.1)]
        ).generate_executive_dashboard()
        assert data["overview"]["high_risk_entities"] == 0

    def test_an_empty_store_reports_zeroes_not_invented_activity(self):
        data = agent().generate_executive_dashboard()
        assert data["overview"]["total_alerts_today"] == 0
        assert data["overview"]["high_risk_entities"] == 0
        assert data["trends"]["alert_volume_change"] == 0.0
        assert data["trends"]["risk_score_trend"] == 0.0
        assert data["performance"]["average_response_time"] == 0.0


class TestSeverityBreakdown:
    def test_buckets_sum_to_the_alert_total(self):
        """The random buckets could not be reconciled against the total."""
        threats = [threat("critical"), threat("high"), threat("high"), threat("low")]
        data = agent(threats=threats).generate_executive_dashboard()
        assert sum(data["alerts_by_severity"].values()) == data["overview"]["total_alerts_today"]

    def test_buckets_hold_the_real_counts(self):
        threats = [threat("critical"), threat("high"), threat("high"), threat("medium")]
        data = agent(threats=threats).generate_executive_dashboard()
        assert data["alerts_by_severity"] == {
            "critical": 1,
            "high": 2,
            "medium": 1,
            "low": 0,
        }

    @pytest.mark.parametrize("severity", ["HIGH", "High", " high "])
    def test_severity_labels_are_normalised(self, severity):
        data = agent(threats=[threat(severity)]).generate_executive_dashboard()
        assert data["alerts_by_severity"]["high"] == 1

    def test_unrecognised_severities_still_reconcile(self):
        data = agent(threats=[threat("catastrophic"), threat("")]).generate_executive_dashboard()
        assert sum(data["alerts_by_severity"].values()) == 2


class TestDashboardTrends:
    def test_volume_change_compares_against_the_prior_day(self):
        threats = [threat(hours_ago=1), threat(hours_ago=2), threat(hours_ago=30)]
        data = agent(threats=threats).generate_executive_dashboard()
        assert data["trends"]["alert_volume_change"] == 1.0

    def test_no_prior_activity_reports_no_change_not_infinity(self):
        data = agent(threats=[threat(hours_ago=1)]).generate_executive_dashboard()
        assert data["trends"]["alert_volume_change"] == 0.0

    def test_risk_trend_is_the_mean_investigation_risk(self):
        data = agent(
            investigations=[investigation("ACC1", 0.4), investigation("ACC2", 0.6)]
        ).generate_executive_dashboard()
        assert data["trends"]["risk_score_trend"] == 0.5

    def test_resolution_time_is_measured_from_real_tasks(self):
        data = agent(tasks=[task(started_ago=3, completed_ago=1)]).generate_executive_dashboard()
        assert data["trends"]["investigation_resolution_time"] == pytest.approx(120.0, abs=1)


class TestDashboardPerformance:
    def test_completed_tasks_are_counted(self):
        data = agent(tasks=[task(), task(), task(completed_ago=None)]).generate_executive_dashboard()
        assert data["performance"]["tasks_completed_today"] == 2

    def test_a_task_completed_without_a_start_still_counts_as_throughput(self):
        data = agent(tasks=[task(started_ago=None, completed_ago=1)]).generate_executive_dashboard()
        assert data["performance"]["tasks_completed_today"] == 1
        assert data["trends"]["investigation_resolution_time"] == 0.0

    def test_agents_online_uses_the_public_accessor(self):
        instance = agent()
        data = instance.generate_executive_dashboard()
        assert data["performance"]["agents_online"] == len(instance._store.get_all_agents())


class TestStoreAccessor:
    def test_get_all_agents_matches_the_reported_agent_count(self):
        store = SOCStore()
        assert len(store.get_all_agents()) == store.get_stats()["total_agents"]

    def test_get_all_agents_returns_a_copy(self):
        """Callers must not be able to mutate the store's internals."""
        store = SOCStore()
        expected = len(store.get_all_agents())

        agents = store.get_all_agents()
        agents.clear()

        assert len(store.get_all_agents()) == expected
