"""Tests that BI charts plot recorded metric values.

Every chart type was filled with random numbers, the label list was a fixed
string list of a different length than the data, and a KPI's current value
fell back to random.uniform(50, 150).
"""

import inspect
from datetime import datetime, timedelta, timezone

import pytest

from src.analytics_business_intelligence import bi_dashboard as bi_dashboard_module
from src.analytics_business_intelligence.bi_dashboard import BIDashboardModule
from src.analytics_business_intelligence.models import (
    BIChart,
    BIDashboard,
    KPI,
    MetricValue,
)
from src.analytics_business_intelligence.store import AnalyticsStore


@pytest.fixture
def store():
    return AnalyticsStore()


@pytest.fixture
def dashboard_module(store):
    return BIDashboardModule(store=store)


def add_chart(store, chart_type="line", data_source="metric_1", series=None, x_axis="region"):
    chart = BIChart(
        name="Chart",
        chart_type=chart_type,
        data_source=data_source,
        x_axis=x_axis,
        y_axis="value",
        series=series or [],
    )
    store.store_chart(chart)
    return chart


def add_value(store, metric_id="metric_1", value=1.0, days_ago=0, region="US"):
    return store.store_metric_value(MetricValue(
        metric_id=metric_id,
        value=value,
        timestamp=datetime.now(timezone.utc) - timedelta(days=days_ago),
        dimensions={"region": region},
    ))


class TestDeterminism:
    """Charts must not be filled with invented numbers."""

    def test_module_does_not_import_random(self):
        source = inspect.getsource(bi_dashboard_module)
        assert "import random" not in source

    def test_repeated_requests_return_the_same_data(self, store, dashboard_module):
        chart = add_chart(store)
        for i in range(3):
            add_value(store, value=float(i), days_ago=i)

        first = dashboard_module.get_chart_data(chart.chart_id, "7d")
        second = dashboard_module.get_chart_data(chart.chart_id, "7d")

        assert first["data"] == second["data"]


class TestTimeSeries:
    """Line and bar charts plot recorded values."""

    def test_values_come_from_the_store(self, store, dashboard_module):
        chart = add_chart(store)
        for i in range(4):
            add_value(store, value=float(i * 10), days_ago=3 - i)

        data = dashboard_module.get_chart_data(chart.chart_id, "7d")

        assert data["data"] == [[0.0, 10.0, 20.0, 30.0]]

    def test_labels_and_points_have_the_same_length(self, store, dashboard_module):
        chart = add_chart(store)
        for i in range(5):
            add_value(store, value=float(i), days_ago=i)

        data = dashboard_module.get_chart_data(chart.chart_id, "7d")

        assert len(data["labels"]) == len(data["data"][0])

    def test_values_outside_the_window_are_excluded(self, store, dashboard_module):
        chart = add_chart(store)
        add_value(store, value=1.0, days_ago=1)
        add_value(store, value=2.0, days_ago=60)

        data = dashboard_module.get_chart_data(chart.chart_id, "7d")

        assert data["data"] == [[1.0]]

    def test_a_wider_range_includes_more(self, store, dashboard_module):
        chart = add_chart(store)
        add_value(store, value=1.0, days_ago=1)
        add_value(store, value=2.0, days_ago=20)

        narrow = dashboard_module.get_chart_data(chart.chart_id, "7d")
        wide = dashboard_module.get_chart_data(chart.chart_id, "30d")

        assert len(wide["data"][0]) > len(narrow["data"][0])

    def test_multiple_series_are_plotted_separately(self, store, dashboard_module):
        chart = add_chart(store, series=["metric_1", "metric_2"])
        add_value(store, metric_id="metric_1", value=5.0)
        add_value(store, metric_id="metric_2", value=9.0)

        data = dashboard_module.get_chart_data(chart.chart_id, "7d")

        assert data["data"] == [[5.0], [9.0]]

    def test_no_recorded_values_is_admitted(self, store, dashboard_module):
        chart = add_chart(store, data_source="never_recorded")

        data = dashboard_module.get_chart_data(chart.chart_id, "7d")

        assert data["data"] == []
        assert data["insufficient_data"] is True

    def test_bar_charts_use_the_same_path(self, store, dashboard_module):
        chart = add_chart(store, chart_type="bar")
        add_value(store, value=7.0)

        assert dashboard_module.get_chart_data(chart.chart_id, "7d")["data"] == [[7.0]]


class TestShareCharts:
    """Pie charts break down real totals."""

    def test_shares_sum_to_one_hundred(self, store, dashboard_module):
        chart = add_chart(store, chart_type="pie")
        add_value(store, value=60.0, region="US")
        add_value(store, value=40.0, region="EU")

        data = dashboard_module.get_chart_data(chart.chart_id, "7d")

        assert sum(data["data"]) == pytest.approx(100.0)

    def test_shares_reflect_the_totals(self, store, dashboard_module):
        chart = add_chart(store, chart_type="pie")
        add_value(store, value=75.0, region="US")
        add_value(store, value=25.0, region="EU")

        data = dashboard_module.get_chart_data(chart.chart_id, "7d")
        shares = dict(zip(data["labels"], data["data"]))

        assert shares["US"] == pytest.approx(75.0)
        assert shares["EU"] == pytest.approx(25.0)

    def test_missing_dimension_is_admitted(self, store, dashboard_module):
        chart = add_chart(store, chart_type="pie", x_axis="not_a_dimension")
        add_value(store, value=10.0)

        data = dashboard_module.get_chart_data(chart.chart_id, "7d")

        assert data["data"] == []
        assert data["insufficient_data"] is True

    def test_generic_charts_return_label_value_pairs(self, store, dashboard_module):
        chart = add_chart(store, chart_type="scatter")
        add_value(store, value=10.0, region="US")

        data = dashboard_module.get_chart_data(chart.chart_id, "7d")

        assert data["data"] == [{"label": "US", "value": 100.0}]


class TestKPIValues:
    """KPI values are never substituted."""

    def _dashboard_with_kpi(self, store, current_value=None, change_percent=None):
        kpi = KPI(
            name="Fraud rate",
            description="",
            metric_id="metric_1",
            target_value=1.0,
            warning_threshold=2.0,
            critical_threshold=3.0,
            current_value=current_value,
            change_percent=change_percent,
            category="risk",
        )
        store.store_kpi(kpi)
        dashboard = BIDashboard(name="D", description="", kpis=[kpi.kpi_id])
        store.store_dashboard(dashboard)
        return dashboard

    def test_unset_value_stays_unset(self, store, dashboard_module):
        dashboard = self._dashboard_with_kpi(store)

        data = dashboard_module.get_dashboard_data(dashboard.dashboard_id)

        assert data["kpis"][0]["current_value"] is None
        assert data["kpis"][0]["change_percent"] is None

    def test_a_recorded_zero_is_preserved(self, store, dashboard_module):
        # `kpi.current_value or random.uniform(50, 150)` replaced a genuine
        # measured value of 0.0 -- a perfect fraud rate reported as ~100.
        dashboard = self._dashboard_with_kpi(store, current_value=0.0, change_percent=0.0)

        data = dashboard_module.get_dashboard_data(dashboard.dashboard_id)

        assert data["kpis"][0]["current_value"] == 0.0
        assert data["kpis"][0]["change_percent"] == 0.0

    def test_a_recorded_value_is_passed_through(self, store, dashboard_module):
        dashboard = self._dashboard_with_kpi(store, current_value=4.2)

        data = dashboard_module.get_dashboard_data(dashboard.dashboard_id)

        assert data["kpis"][0]["current_value"] == 4.2
