"""Tests that segmentation and cohort analysis read their inputs.

segment_entities used `entities` only for its length and drew every metric,
the whole risk distribution and all five "characteristics" from random.
perform_cohort_analysis manufactured a decay curve for a cohort nobody had
observed.
"""

import inspect

import pytest

from src.analytics_business_intelligence import (
    advanced_analytics as advanced_analytics_module,
)
from src.analytics_business_intelligence.advanced_analytics import (
    AdvancedAnalyticsModule,
)
from src.analytics_business_intelligence.store import AnalyticsStore


@pytest.fixture
def analytics():
    return AdvancedAnalyticsModule(store=AnalyticsStore())


def entity(risk=0.5, volume=1000, fraud=False, tier="gold"):
    return {
        "risk_score": risk,
        "transaction_volume": volume,
        "is_fraud": fraud,
        "tier": tier,
    }


class TestDeterminism:
    """The module no longer manufactures analytics."""

    def test_module_does_not_import_random(self):
        source = inspect.getsource(advanced_analytics_module)
        assert "import random" not in source

    def test_repeated_segmentation_agrees(self, analytics):
        entities = [entity(risk=0.9), entity(risk=0.2)]

        first = analytics.segment_entities(entities, {"name": "S"})
        second = analytics.segment_entities(entities, {"name": "S"})

        assert first.metrics == second.metrics
        assert first.risk_distribution == second.risk_distribution


class TestSegmentMetrics:
    """Metrics are averaged from the entities."""

    def test_average_risk_score_is_the_mean(self, analytics):
        segment = analytics.segment_entities(
            [entity(risk=0.2), entity(risk=0.8)], {"name": "S"},
        )

        assert segment.metrics["avg_risk_score"] == pytest.approx(0.5)

    def test_fraud_rate_counts_flagged_entities(self, analytics):
        segment = analytics.segment_entities(
            [entity(fraud=True), entity(fraud=False),
             entity(fraud=False), entity(fraud=False)],
            {"name": "S"},
        )

        assert segment.metrics["fraud_rate"] == pytest.approx(0.25)

    def test_absent_metrics_are_omitted_not_invented(self, analytics):
        segment = analytics.segment_entities([{"tier": "gold"}], {"name": "S"})

        assert "avg_risk_score" not in segment.metrics
        assert "fraud_rate" not in segment.metrics

    def test_empty_segment_has_no_metrics(self, analytics):
        segment = analytics.segment_entities([], {"name": "S"})

        assert segment.metrics == {}
        assert segment.size == 0


class TestRiskDistribution:
    """The distribution describes the entities in the segment."""

    def test_counts_sum_to_the_segment_size(self, analytics):
        entities = [entity(risk=r) for r in (0.95, 0.7, 0.5, 0.1, 0.3)]

        segment = analytics.segment_entities(entities, {"name": "S"})

        assert sum(segment.risk_distribution.values()) == len(entities)

    def test_entities_land_in_the_right_band(self, analytics):
        segment = analytics.segment_entities(
            [entity(risk=0.95), entity(risk=0.65), entity(risk=0.45), entity(risk=0.1)],
            {"name": "S"},
        )

        assert segment.risk_distribution == {
            "critical": 1, "high": 1, "medium": 1, "low": 1,
        }

    def test_empty_segment_distributes_nothing(self, analytics):
        segment = analytics.segment_entities([], {"name": "S"})

        assert sum(segment.risk_distribution.values()) == 0

    def test_entities_without_a_score_are_not_counted(self, analytics):
        segment = analytics.segment_entities(
            [entity(risk=0.9), {"tier": "gold"}], {"name": "S"},
        )

        assert sum(segment.risk_distribution.values()) == 1


class TestSegmentShare:
    """Percentage is computed against a known population."""

    def test_share_of_the_population(self, analytics):
        segment = analytics.segment_entities(
            [entity() for _ in range(3)], {"name": "S"}, population_size=30,
        )

        assert segment.percentage == pytest.approx(10.0)

    def test_population_size_can_come_from_the_definition(self, analytics):
        segment = analytics.segment_entities(
            [entity() for _ in range(5)],
            {"name": "S", "population_size": 20},
        )

        assert segment.percentage == pytest.approx(25.0)

    def test_unknown_population_reports_no_share(self, analytics):
        segment = analytics.segment_entities([entity()], {"name": "S"})

        assert segment.percentage is None


class TestTopCharacteristics:
    """Characteristics describe the segment's actual attributes."""

    def test_shared_attributes_are_reported(self, analytics):
        entities = [entity(tier="gold"), entity(tier="gold"), entity(tier="silver")]

        segment = analytics.segment_entities(entities, {"name": "S"})

        assert any("tier=gold" in c for c in segment.top_characteristics)

    def test_no_placeholder_characteristics(self, analytics):
        segment = analytics.segment_entities(
            [entity(), entity()], {"name": "S"},
        )

        assert not any(
            c.startswith("Characteristic ") for c in segment.top_characteristics
        )

    def test_empty_segment_has_no_characteristics(self, analytics):
        assert analytics.segment_entities([], {"name": "S"}).top_characteristics == []


class TestCohortAnalysis:
    """Retention is measured against observations."""

    def test_retention_is_relative_to_the_initial_cohort(self, analytics):
        cohort = analytics.perform_cohort_analysis(
            "c", {}, active_counts=[100, 80, 60, 40],
        )

        assert cohort.retention_rates == [100.0, 80.0, 60.0, 40.0]

    def test_average_and_churn_follow_the_rates(self, analytics):
        cohort = analytics.perform_cohort_analysis(
            "c", {}, active_counts=[100, 80, 60, 40],
        )

        assert cohort.average_retention == pytest.approx(70.0)
        assert cohort.churn_rate == pytest.approx(30.0)

    def test_period_count_matches_the_observations(self, analytics):
        cohort = analytics.perform_cohort_analysis(
            "c", {}, retention_periods=12, active_counts=[50, 25],
        )

        assert cohort.period_count == 2

    def test_no_observations_reports_no_retention(self, analytics):
        cohort = analytics.perform_cohort_analysis("c", {})

        assert cohort.retention_rates == []
        assert cohort.average_retention is None
        assert cohort.churn_rate is None

    def test_zero_initial_cohort_does_not_divide_by_zero(self, analytics):
        cohort = analytics.perform_cohort_analysis("c", {}, active_counts=[0, 0])

        assert cohort.retention_rates == []

    def test_growing_cohort_is_not_clamped(self, analytics):
        # Retention above 100% is unusual but real (re-activation); it must
        # not be silently floored the way the old decay curve was.
        cohort = analytics.perform_cohort_analysis(
            "c", {}, active_counts=[100, 120],
        )

        assert cohort.retention_rates == [100.0, 120.0]
