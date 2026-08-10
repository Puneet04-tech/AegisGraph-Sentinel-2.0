"""Tests that correlation significance and seasonality are computed.

The p-value was ``random.uniform(0.001, 0.05)`` -- always below 0.05, so every
correlation was reported as statistically significant. Seasonality was
``random.choice([True, False])``.
"""

import inspect
import math

import pytest

from src.analytics_business_intelligence.advanced_analytics import (
    AdvancedAnalyticsModule,
)
from src.analytics_business_intelligence.store import AnalyticsStore


@pytest.fixture
def analytics():
    return AdvancedAnalyticsModule(store=AnalyticsStore())


def now_range():
    from datetime import datetime, timezone
    moment = datetime.now(timezone.utc)
    return moment, moment


class TestDeterminism:
    """Statistics must not be drawn."""

    def test_statistics_do_not_use_random(self):
        # Segmentation in this module still fabricates its figures; that is a
        # separate defect. Nothing on the correlation or seasonality paths may
        # touch random.
        for function in (
            AdvancedAnalyticsModule.analyze_correlation,
            AdvancedAnalyticsModule._correlation_p_value,
            AdvancedAnalyticsModule._detect_seasonality,
            AdvancedAnalyticsModule._autocorrelation,
            AdvancedAnalyticsModule.analyze_trend,
        ):
            code = "\n".join(
                line for line in inspect.getsource(function).splitlines()
                if not line.strip().startswith("#")
            )
            assert "random" not in code

    def test_repeated_correlations_agree(self, analytics):
        a = [1, 2, 3, 4, 5, 6, 7, 8]
        b = [2, 4, 5, 4, 6, 8, 9, 11]

        first = analytics.analyze_correlation(a, b)
        second = analytics.analyze_correlation(a, b)

        assert first.p_value == second.p_value
        assert first.significance == second.significance

    def test_repeated_trend_seasonality_agrees(self, analytics):
        series = [float(i % 7) for i in range(60)]
        start, end = now_range()

        first = analytics.analyze_trend("m", series, start, end)
        second = analytics.analyze_trend("m", series, start, end)

        assert first.seasonality_detected == second.seasonality_detected


class TestCorrelationSignificance:
    """The p-value reflects the data."""

    def test_unrelated_variables_are_not_significant(self, analytics):
        a = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        b = [5, 5, 5, 5.1, 4.9, 5, 5.05, 4.95, 5, 5.02]

        result = analytics.analyze_correlation(a, b)

        assert result.p_value > 0.05
        assert result.significance == "LOW"

    def test_strong_relationship_is_significant(self, analytics):
        a = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        b = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]

        result = analytics.analyze_correlation(a, b)

        assert result.p_value < 0.05
        assert result.significance == "HIGH"

    def test_p_value_stays_in_range(self, analytics):
        a = [1, 2, 3, 4, 5, 6]
        b = [3, 1, 4, 1, 5, 9]

        result = analytics.analyze_correlation(a, b)

        assert 0.0 <= result.p_value <= 1.0

    def test_more_data_strengthens_the_same_relationship(self, analytics):
        small_a = [1, 2, 3, 4]
        small_b = [1.0, 2.1, 2.9, 4.2]
        large_a = small_a * 5
        large_b = small_b * 5

        small = analytics.analyze_correlation(small_a, small_b)
        large = analytics.analyze_correlation(large_a, large_b)

        # Same coefficient, more evidence -> smaller p-value.
        assert large.correlation_coefficient == pytest.approx(
            small.correlation_coefficient, abs=1e-6,
        )
        assert large.p_value < small.p_value

    def test_perfect_correlation_does_not_produce_nan(self, analytics):
        a = [1, 2, 3, 4, 5]
        result = analytics.analyze_correlation(a, a)

        assert not math.isnan(result.p_value)
        assert result.p_value == 0.0

    def test_negative_correlation_is_also_testable(self, analytics):
        a = [1, 2, 3, 4, 5, 6, 7, 8]
        b = [8, 7, 6, 5, 4, 3, 2, 1]

        result = analytics.analyze_correlation(a, b)

        assert result.correlation_coefficient < 0
        assert result.p_value < 0.05
        assert result.significance == "HIGH"

    def test_large_coefficient_on_tiny_sample_is_not_high(self, analytics):
        # A coefficient of 0.5 over three points is indistinguishable from
        # chance; it must not be graded on magnitude alone.
        result = analytics.analyze_correlation([1, 2, 3], [1, 3, 2])

        assert result.p_value > 0.05
        assert result.significance == "LOW"


class TestSeasonality:
    """Seasonality is measured by autocorrelation."""

    def _trend(self, analytics, series):
        start, end = now_range()
        return analytics.analyze_trend("metric", series, start, end)

    def test_weekly_cycle_is_detected(self, analytics):
        series = [float(i % 7) for i in range(60)]

        assert self._trend(analytics, series).seasonality_detected is True

    def test_flat_series_is_not_seasonal(self, analytics):
        assert self._trend(analytics, [5.0] * 60).seasonality_detected is False

    def test_short_series_is_not_seasonal(self, analytics):
        # Fewer than two full cycles is not evidence of a cycle.
        series = [float(i % 7) for i in range(8)]

        assert self._trend(analytics, series).seasonality_detected is False

    def test_autocorrelation_of_a_constant_series_is_zero(self, analytics):
        assert analytics._autocorrelation([3.0] * 30, 7) == 0.0

    def test_autocorrelation_is_high_at_the_true_period(self, analytics):
        series = [float(i % 7) for i in range(70)]

        at_period = analytics._autocorrelation(series, 7)
        off_period = analytics._autocorrelation(series, 30)

        assert at_period > off_period
