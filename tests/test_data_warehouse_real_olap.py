"""Tests that data warehouse operations query the warehouse.

Every OLAP operation returned random numbers, cube_name was never resolved
against anything, and created cubes were discarded rather than stored.
"""

import inspect

import pytest

from src.analytics_business_intelligence import data_warehouse as data_warehouse_module
from src.analytics_business_intelligence.data_warehouse import DataWarehouseModule
from src.analytics_business_intelligence.models import AggregationType, MetricValue
from src.analytics_business_intelligence.store import AnalyticsStore


@pytest.fixture
def store():
    return AnalyticsStore()


@pytest.fixture
def warehouse(store):
    return DataWarehouseModule(store=store)


def add_fact(store, metric_id="sales", value=100.0, region="US", channel="web"):
    return store.store_metric_value(MetricValue(
        metric_id=metric_id,
        value=value,
        dimensions={"region": region, "channel": channel},
    ))


@pytest.fixture
def populated(store, warehouse):
    add_fact(store, value=100.0, region="US")
    add_fact(store, value=200.0, region="US")
    add_fact(store, value=300.0, region="EU")
    return warehouse.create_data_cube("Sales", ["region", "channel"], ["sales"])


class TestDeterminism:
    """OLAP results must be reproducible."""

    def test_module_does_not_import_random(self):
        source = inspect.getsource(data_warehouse_module)
        assert "import random" not in source

    def test_repeated_queries_agree(self, warehouse, populated):
        first = warehouse.query_cube("Sales", measures=["sales"])
        second = warehouse.query_cube("Sales", measures=["sales"])

        assert first == second


class TestCubeCreation:
    """A cube describes the facts behind it and is retrievable."""

    def test_facts_count_recorded_values(self, warehouse, populated):
        assert populated.facts == 3

    def test_empty_warehouse_makes_an_empty_cube(self, warehouse):
        cube = warehouse.create_data_cube("Empty", ["region"], ["sales"])

        assert cube.facts == 0

    def test_cube_is_stored_and_findable(self, store, warehouse, populated):
        assert store.get_cube_by_name("Sales") is not None

    def test_aggregations_sum_the_facts(self, warehouse, populated):
        aggregation = populated.aggregations["region_sales_sum"]

        assert aggregation["value"] == pytest.approx(600.0)
        assert aggregation["fact_count"] == 3


class TestQueryCube:
    """Queries group and aggregate real facts."""

    def test_unknown_cube_returns_nothing(self, warehouse):
        assert warehouse.query_cube("NoSuchCube") == []

    def test_rows_are_grouped_by_dimension(self, warehouse, populated):
        rows = warehouse.query_cube("Sales", measures=["sales"])

        by_region = {row["region"]: row["sales"] for row in rows}
        assert by_region == {"US": pytest.approx(300.0), "EU": pytest.approx(300.0)}

    def test_average_aggregation(self, warehouse, populated):
        rows = warehouse.query_cube(
            "Sales", dimensions={"region": "US"}, measures=["sales"],
            aggregation=AggregationType.AVG,
        )

        assert rows[0]["sales"] == pytest.approx(150.0)

    def test_count_aggregation(self, warehouse, populated):
        rows = warehouse.query_cube(
            "Sales", dimensions={"region": "US"}, measures=["sales"],
            aggregation=AggregationType.COUNT,
        )

        assert rows[0]["sales"] == 2

    def test_min_and_max_aggregations(self, warehouse, populated):
        minimum = warehouse.query_cube(
            "Sales", dimensions={"region": "US"}, measures=["sales"],
            aggregation=AggregationType.MIN,
        )[0]["sales"]
        maximum = warehouse.query_cube(
            "Sales", dimensions={"region": "US"}, measures=["sales"],
            aggregation=AggregationType.MAX,
        )[0]["sales"]

        assert minimum == pytest.approx(100.0)
        assert maximum == pytest.approx(200.0)

    def test_filters_actually_filter(self, warehouse, populated):
        rows = warehouse.query_cube(
            "Sales", filters={"region": "EU"}, measures=["sales"],
        )

        assert len(rows) == 1
        assert rows[0]["sales"] == pytest.approx(300.0)

    def test_filter_matching_nothing_returns_nothing(self, warehouse, populated):
        assert warehouse.query_cube("Sales", filters={"region": "APAC"}) == []


class TestRollup:
    """Rollups total the facts."""

    def test_totals_come_from_the_facts(self, warehouse, populated):
        rollup = warehouse.rollup_cube("Sales", ["region"])

        assert rollup["total_records"] == 3
        assert rollup["aggregated_values"]["region"] == pytest.approx(600.0)

    def test_unknown_cube_is_reported(self, warehouse):
        rollup = warehouse.rollup_cube("NoSuchCube", ["region"])

        assert rollup["cube_found"] is False
        assert rollup["total_records"] == 0


class TestDrilldown:
    """Drilldown breaks facts out by dimension value."""

    def test_values_are_real_dimension_values(self, warehouse, populated):
        rows = warehouse.drilldown_cube("Sales", "region")

        assert {row["value"] for row in rows} == {"US", "EU"}

    def test_no_placeholder_detail_values(self, warehouse, populated):
        rows = warehouse.drilldown_cube("Sales", "region")

        assert not any(str(row["value"]).startswith("detail_") for row in rows)

    def test_counts_and_totals_match_the_facts(self, warehouse, populated):
        rows = {r["value"]: r for r in warehouse.drilldown_cube("Sales", "region")}

        assert rows["US"]["count"] == 2
        assert rows["US"]["total"] == pytest.approx(300.0)

    def test_unknown_dimension_yields_nothing(self, warehouse, populated):
        assert warehouse.drilldown_cube("Sales", "not_a_dimension") == []


class TestSlice:
    """Slices count the matching facts."""

    def test_slice_counts_matching_facts(self, warehouse, populated):
        result = warehouse.slice_cube("Sales", "region", "US")

        assert result["record_count"] == 2
        assert result["total"] == pytest.approx(300.0)

    def test_slice_with_no_matches_is_zero(self, warehouse, populated):
        result = warehouse.slice_cube("Sales", "region", "APAC")

        assert result["record_count"] == 0
        assert result["total"] == 0.0

    def test_unknown_cube_is_reported(self, warehouse):
        assert warehouse.slice_cube("NoSuchCube", "region", "US")["cube_found"] is False


class TestTimeSeries:
    """An unrecorded metric is not filled in."""

    def test_missing_metric_returns_nothing(self, warehouse):
        assert warehouse.get_metric_time_series("never_recorded", period_days=7) == []

    def test_recorded_values_are_returned(self, store, warehouse):
        add_fact(store, metric_id="latency", value=42.0)

        series = warehouse.get_metric_time_series("latency", period_days=7)

        assert len(series) == 1
