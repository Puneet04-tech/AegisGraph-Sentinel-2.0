"""Tests that risk scorecards are scored from recorded governance items.

Category scores, the overall trend, per-category trends, every risk indicator
and the entire metric trend analysis previously came from ``random``.
"""

import inspect
from datetime import datetime, timedelta, timezone

import pytest

from src.executive_governance import risk_governance as risk_governance_module
from src.executive_governance.models import (
    AuditFinding,
    AuditFindingSeverity,
    GovernanceMetric,
    PolicyViolation,
)
from src.executive_governance.risk_governance import RiskGovernanceModule
from src.executive_governance.store import GovernanceStore


@pytest.fixture
def store():
    return GovernanceStore()


@pytest.fixture
def governance(store):
    return RiskGovernanceModule(store=store)


def add_finding(
    store,
    category="fraud_detection",
    severity=AuditFindingSeverity.HIGH,
    risk_impact=0.7,
    entities=(),
    status="OPEN",
):
    return store.store_finding(AuditFinding(
        finding_title="finding",
        description="description",
        severity=severity,
        category=category,
        risk_impact=risk_impact,
        affected_entities=list(entities),
        status=status,
    ))


def add_metric(store, name, value, age_days=0):
    return store.store_metric(GovernanceMetric(
        name=name,
        value=value,
        unit="score",
        category="risk",
        trend="stable",
        change_percent=0.0,
        timestamp=datetime.now(timezone.utc) - timedelta(days=age_days),
    ))


class TestDeterminism:
    """The module must not manufacture risk figures."""

    def test_module_does_not_import_random(self):
        source = inspect.getsource(risk_governance_module)
        assert "import random" not in source

    def test_repeated_scorecards_over_same_data_agree(self, store, governance):
        add_finding(store)
        add_finding(store, category="cyber_intrusion")

        first = governance.generate_risk_scorecard()
        second = governance.generate_risk_scorecard()

        assert first.risk_categories == second.risk_categories
        assert first.risk_indicators == second.risk_indicators


class TestCategoryScoring:
    """Category scores follow the open findings attributed to them."""

    def test_empty_store_scores_zero_not_a_baseline(self, governance):
        scorecard = governance.generate_risk_scorecard()

        assert set(scorecard.risk_categories.values()) == {0.0}
        assert scorecard.overall_risk_score == 0.0

    def test_findings_raise_their_own_category_only(self, store, governance):
        add_finding(store, category="fraud_detection", risk_impact=0.9)

        categories = governance.generate_risk_scorecard().risk_categories

        assert categories["fraud_risk"] > 0
        assert categories["cyber_risk"] == 0.0
        assert categories["operational_risk"] == 0.0

    def test_severity_raises_the_score(self, store, governance):
        add_finding(store, severity=AuditFindingSeverity.LOW, risk_impact=0.1)
        low = governance.generate_risk_scorecard().risk_categories["fraud_risk"]

        store._findings.clear()
        add_finding(store, severity=AuditFindingSeverity.CRITICAL, risk_impact=1.0)
        critical = governance.generate_risk_scorecard().risk_categories["fraud_risk"]

        assert critical > low

    def test_volume_raises_the_score(self, store, governance):
        add_finding(store, risk_impact=0.5)
        one = governance.generate_risk_scorecard().risk_categories["fraud_risk"]

        for _ in range(5):
            add_finding(store, risk_impact=0.5)
        many = governance.generate_risk_scorecard().risk_categories["fraud_risk"]

        assert many > one

    def test_closed_findings_do_not_score(self, store, governance):
        add_finding(store, status="CLOSED")

        categories = governance.generate_risk_scorecard().risk_categories

        assert categories["fraud_risk"] == 0.0

    def test_policy_violations_are_not_double_counted_as_compliance(
        self, store, governance,
    ):
        # Every PolicyViolation name contains "Policy"; it must not therefore
        # land in compliance_risk on top of its real category.
        store.store_violation(PolicyViolation(
            policy_id="p1",
            policy_name="Fraud Monitoring Policy",
            entity_id="e1",
            entity_type="account",
            severity=AuditFindingSeverity.HIGH,
            description="violation",
        ))

        categories = governance.generate_risk_scorecard().risk_categories

        assert categories["fraud_risk"] > 0
        assert categories["compliance_risk"] == 0.0


class TestTrends:
    """Trends compare against the previous scorecard, not a random choice."""

    def test_first_scorecard_admits_no_history(self, governance):
        assert governance.generate_risk_scorecard().risk_trend == "insufficient_history"

    def test_rising_risk_reports_increasing(self, store, governance):
        governance.generate_risk_scorecard()
        for _ in range(6):
            add_finding(store, severity=AuditFindingSeverity.CRITICAL, risk_impact=1.0)

        assert governance.generate_risk_scorecard().risk_trend == "increasing"

    def test_falling_risk_reports_decreasing(self, store, governance):
        for _ in range(6):
            add_finding(store, severity=AuditFindingSeverity.CRITICAL, risk_impact=1.0)
        governance.generate_risk_scorecard()

        store._findings.clear()

        assert governance.generate_risk_scorecard().risk_trend == "decreasing"

    def test_unchanged_risk_reports_stable(self, store, governance):
        add_finding(store)
        governance.generate_risk_scorecard()

        assert governance.generate_risk_scorecard().risk_trend == "stable"


class TestKeyRisks:
    """Key risks are the categories that actually carry risk."""

    def test_zero_scoring_categories_are_not_key_risks(self, store, governance):
        add_finding(store, category="fraud_detection")

        key_risks = governance.generate_risk_scorecard().key_risks

        assert [r["risk_category"] for r in key_risks] == ["fraud_risk"]

    def test_key_risks_are_ranked_by_score(self, store, governance):
        add_finding(store, category="fraud_detection", severity=AuditFindingSeverity.CRITICAL, risk_impact=1.0)
        add_finding(store, category="cyber_intrusion", severity=AuditFindingSeverity.LOW, risk_impact=0.1)

        key_risks = governance.generate_risk_scorecard().key_risks

        assert [r["risk_category"] for r in key_risks] == ["fraud_risk", "cyber_risk"]


class TestRiskIndicators:
    """Indicators are counted from the store."""

    def test_indicators_count_open_items(self, store, governance):
        add_finding(store, severity=AuditFindingSeverity.CRITICAL, entities=["e1", "e2"])
        add_finding(store, severity=AuditFindingSeverity.LOW, entities=["e2"])
        store.store_violation(PolicyViolation(
            policy_id="p1",
            policy_name="Fraud Policy",
            entity_id="e3",
            entity_type="account",
            severity=AuditFindingSeverity.HIGH,
            description="violation",
        ))

        indicators = governance.generate_risk_scorecard().risk_indicators

        assert indicators["open_findings"] == 2
        assert indicators["critical_findings"] == 1
        assert indicators["open_policy_violations"] == 1
        # e1, e2, e3 -- deduplicated across findings and violations.
        assert indicators["high_risk_entities"] == 3


class TestMetricTrend:
    """Metric trends read the recorded metric history."""

    def test_no_history_is_reported_as_such(self, governance):
        trend = governance.track_risk_trend("risk_score")

        assert trend["current_value"] is None
        assert trend["trend"] == "insufficient_history"
        assert trend["observations"] == 0

    def test_current_value_is_the_latest_observation(self, store, governance):
        add_metric(store, "risk_score", 0.2, age_days=20)
        add_metric(store, "risk_score", 0.9, age_days=0)

        assert governance.track_risk_trend("risk_score")["current_value"] == 0.9

    def test_rising_metric_reports_increasing(self, store, governance):
        add_metric(store, "risk_score", 0.2, age_days=25)
        add_metric(store, "risk_score", 0.3, age_days=20)
        add_metric(store, "risk_score", 0.9, age_days=0)

        assert governance.track_risk_trend("risk_score")["trend"] == "increasing"

    def test_flat_metric_reports_stable(self, store, governance):
        for age in (25, 15, 0):
            add_metric(store, "risk_score", 0.5, age_days=age)

        trend = governance.track_risk_trend("risk_score")

        assert trend["trend"] == "stable"
        assert trend["volatility"] == 0.0

    def test_other_metrics_are_not_mixed_in(self, store, governance):
        add_metric(store, "risk_score", 0.5)
        add_metric(store, "unrelated_metric", 0.9)

        assert governance.track_risk_trend("risk_score")["observations"] == 1

    def test_volatility_reflects_spread(self, store, governance):
        add_metric(store, "steady", 0.5, age_days=2)
        add_metric(store, "steady", 0.5, age_days=1)
        add_metric(store, "swingy", 0.1, age_days=2)
        add_metric(store, "swingy", 0.9, age_days=1)

        steady = governance.track_risk_trend("steady")["volatility"]
        swingy = governance.track_risk_trend("swingy")["volatility"]

        assert swingy > steady
