"""
Tests for Advanced Analytics & Business Intelligence Platform.

Comprehensive tests for:
    - Data Warehouse
    - BI Dashboard
    - Advanced Analytics
    - KPI Engine
    - Report Automation
"""

import pytest
from datetime import datetime, timezone, timedelta

from src.analytics_business_intelligence import (
    MetricType,
    AggregationType,
    ReportSchedule,
    KPI,
    TrendAnalysis,
    CorrelationResult,
    SegmentAnalysis,
    AnalyticsStore,
    get_analytics_store,
    DataWarehouseModule,
    get_data_warehouse_module,
    BIDashboardModule,
    get_bi_dashboard_module,
    AdvancedAnalyticsModule,
    get_advanced_analytics_module,
    KPIEngineModule,
    get_kpi_engine_module,
    ReportAutomationModule,
    get_report_automation_module,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def store():
    """Create a fresh analytics store for testing."""
    return AnalyticsStore(max_size=100)


@pytest.fixture
def data_warehouse(store):
    """Create a data warehouse module."""
    return DataWarehouseModule(store=store)


@pytest.fixture
def bi_dashboard(store):
    """Create a BI dashboard module."""
    return BIDashboardModule(store=store)


@pytest.fixture
def advanced_analytics(store):
    """Create an advanced analytics module."""
    return AdvancedAnalyticsModule(store=store)


@pytest.fixture
def kpi_engine(store):
    """Create a KPI engine module."""
    return KPIEngineModule(store=store)


@pytest.fixture
def report_automation(store):
    """Create a report automation module."""
    return ReportAutomationModule(store=store)


# =============================================================================
# Store Tests
# =============================================================================

class TestAnalyticsStore:
    """Tests for AnalyticsStore."""
    
    def test_store_and_retrieve_kpi(self, store):
        """Test storing and retrieving KPIs."""
        kpi = KPI(
            name="Test KPI",
            description="Test description",
            metric_id="test_metric",
            target_value=100.0,
            warning_threshold=80.0,
            critical_threshold=60.0,
            category="Test",
        )
        
        stored = store.store_kpi(kpi)
        retrieved = store.get_kpi(kpi.kpi_id)
        
        assert retrieved is not None
        assert retrieved.name == "Test KPI"
    
    def test_get_all_kpis(self, store):
        """Test getting all KPIs."""
        kpis = store.get_all_kpis()
        assert len(kpis) >= 3  # Default KPIs
    
    def test_get_kpis_by_status(self, store):
        """Test getting KPIs by status."""
        on_target = store.get_kpis_by_status("ON_TARGET")
        assert isinstance(on_target, list)
    
    def test_store_and_retrieve_trend(self, store):
        """Test storing and retrieving trends."""
        now = datetime.now(timezone.utc)
        trend = TrendAnalysis(
            metric_name="test_metric",
            period_start=now - timedelta(days=30),
            period_end=now,
            direction="increasing",
            slope=0.5,
            volatility=10.0,
        )
        
        stored = store.store_trend(trend)
        retrieved = store.get_trend(trend.analysis_id)
        
        assert retrieved is not None
        assert retrieved.metric_name == "test_metric"
    
    def test_get_stats(self, store):
        """Test getting store statistics."""
        stats = store.get_stats()
        
        assert "kpis_stored" in stats
        assert "dashboards_stored" in stats
        assert "insights_stored" in stats


# =============================================================================
# Data Warehouse Tests
# =============================================================================

class TestDataWarehouse:
    """Tests for DataWarehouseModule."""
    
    def test_create_data_cube(self, data_warehouse):
        """Test creating a data cube."""
        cube = data_warehouse.create_data_cube(
            name="Test Cube",
            dimensions=["time", "location"],
            measures=["count", "total"],
        )
        
        assert cube.name == "Test Cube"
        assert len(cube.dimensions) == 2
    
    def test_query_cube(self, data_warehouse):
        """Test querying a cube."""
        results = data_warehouse.query_cube(
            cube_name="test_cube",
            dimensions={"time": "2024"},
            measures=["count"],
        )
        
        assert isinstance(results, list)
    
    def test_define_metric(self, data_warehouse):
        """Test defining a metric."""
        metric = data_warehouse.define_metric(
            name="Test Metric",
            description="Test metric description",
            metric_type=MetricType.COUNTER,
            aggregation=AggregationType.SUM,
            category="Test",
            unit="count",
        )
        
        assert metric.metric_id is not None
        assert metric.name == "Test Metric"
    
    def test_record_metric_value(self, data_warehouse):
        """Test recording a metric value."""
        metric = data_warehouse.define_metric(
            name="Record Test",
            description="Test",
            metric_type=MetricType.GAUGE,
            aggregation=AggregationType.AVG,
            category="Test",
            unit="value",
        )
        
        value = data_warehouse.record_metric_value(
            metric_id=metric.metric_id,
            value=100.0,
            dimensions={"source": "test"},
        )
        
        assert value.value_id is not None
        assert value.value == 100.0


# =============================================================================
# BI Dashboard Tests
# =============================================================================

class TestBIDashboard:
    """Tests for BIDashboardModule."""
    
    def test_create_chart(self, bi_dashboard):
        """Test creating a chart."""
        chart = bi_dashboard.create_chart(
            name="Test Chart",
            chart_type="line",
            data_source="test_source",
            x_axis="time",
            y_axis="value",
        )
        
        assert chart.chart_id is not None
        assert chart.chart_type == "line"
    
    def test_create_dashboard(self, bi_dashboard):
        """Test creating a dashboard."""
        dashboard = bi_dashboard.create_dashboard(
            name="Test Dashboard",
            description="Test dashboard description",
            refresh_interval=300,
            created_by="test_user",
        )
        
        assert dashboard.dashboard_id is not None
        assert dashboard.name == "Test Dashboard"
    
    def test_get_chart_data(self, bi_dashboard):
        """Test getting chart data."""
        chart = bi_dashboard.create_chart(
            name="Data Chart",
            chart_type="bar",
            data_source="test",
            x_axis="category",
            y_axis="value",
        )
        
        data = bi_dashboard.get_chart_data(chart.chart_id)
        
        assert "chart_id" in data
        assert "data" in data
    
    def test_get_default_dashboards(self, bi_dashboard):
        """Test getting default dashboards."""
        defaults = bi_dashboard.get_default_dashboards()
        
        assert len(defaults) == 3
        assert any(d["id"] == "fraud_overview" for d in defaults)


# =============================================================================
# Advanced Analytics Tests
# =============================================================================

class TestAdvancedAnalytics:
    """Tests for AdvancedAnalyticsModule."""
    
    def test_analyze_trend(self, advanced_analytics):
        """Test trend analysis."""
        data_points = [10, 12, 15, 14, 18, 20, 19, 22, 25, 24]
        now = datetime.now(timezone.utc)
        
        analysis = advanced_analytics.analyze_trend(
            metric_name="test_metric",
            data_points=data_points,
            period_start=now - timedelta(days=30),
            period_end=now,
        )
        
        assert analysis.analysis_id is not None
        assert analysis.metric_name == "test_metric"
        assert analysis.direction in ["increasing", "decreasing", "stable"]
    
    def test_analyze_correlation(self, advanced_analytics):
        """Test correlation analysis."""
        variable_a = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        variable_b = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
        
        result = advanced_analytics.analyze_correlation(
            variable_a=variable_a,
            variable_b=variable_b,
            variable_a_name="Variable A",
            variable_b_name="Variable B",
        )
        
        assert result.correlation_id is not None
        assert -1 <= result.correlation_coefficient <= 1
    
    def test_segment_entities(self, advanced_analytics):
        """Test entity segmentation."""
        entities = [
            {"id": f"entity_{i}", "risk_score": 0.5 + i * 0.05}
            for i in range(100)
        ]
        
        segment = advanced_analytics.segment_entities(
            entities=entities,
            segment_definition={"name": "High Risk Segment"},
        )
        
        assert segment.segment_id is not None
        assert segment.size == 100
    
    def test_detect_anomalies(self, advanced_analytics):
        """Test anomaly detection."""
        data = [10, 12, 11, 50, 13, 14, 12, 11, 10, 12]  # 50 is anomaly
        
        anomalies = advanced_analytics.detect_anomalies(data, threshold=2.0)
        
        assert len(anomalies) >= 1
    
    def test_calculate_descriptive_stats(self, advanced_analytics):
        """Test descriptive statistics."""
        data = [10, 20, 30, 40, 50]
        
        stats = advanced_analytics.calculate_descriptive_stats(data)
        
        assert "mean" in stats
        assert "median" in stats
        assert "std_dev" in stats


# =============================================================================
# KPI Engine Tests
# =============================================================================

class TestKPIEngine:
    """Tests for KPIEngineModule."""
    
    def test_create_kpi(self, kpi_engine):
        """Test creating a KPI."""
        kpi = kpi_engine.create_kpi(
            name="Test KPI",
            description="Test description",
            metric_id="test_metric",
            target_value=100.0,
            warning_threshold=80.0,
            critical_threshold=60.0,
            category="Test",
        )
        
        assert kpi.kpi_id is not None
        assert kpi.name == "Test KPI"
    
    def test_update_kpi_value(self, kpi_engine):
        """Test updating KPI value."""
        kpi = kpi_engine.create_kpi(
            name="Update Test",
            description="Test",
            metric_id="update_test",
            target_value=100.0,
            warning_threshold=80.0,
            critical_threshold=60.0,
            category="Test",
        )
        
        updated = kpi_engine.update_kpi_value(kpi.kpi_id, 95.0)
        
        assert updated.current_value == 95.0
        assert updated.status in ["ON_TARGET", "WARNING", "CRITICAL"]
    
    def test_monitor_thresholds(self, kpi_engine):
        """Test threshold monitoring."""
        alerts = kpi_engine.monitor_thresholds()
        
        assert isinstance(alerts, list)
    
    def test_get_kpi_dashboard(self, kpi_engine):
        """Test getting KPI dashboard."""
        dashboard = kpi_engine.get_kpi_dashboard()
        
        assert "total_kpis" in dashboard
        assert "health_score" in dashboard
    
    def test_get_trending_kpis(self, kpi_engine):
        """Test getting trending KPIs."""
        trending = kpi_engine.get_trending_kpis()
        
        assert isinstance(trending, list)


# =============================================================================
# Report Automation Tests
# =============================================================================

class TestReportAutomation:
    """Tests for ReportAutomationModule."""
    
    def test_create_scheduled_report(self, report_automation):
        """Test creating scheduled report."""
        report = report_automation.create_scheduled_report(
            name="Test Report",
            description="Test report description",
            schedule=ReportSchedule.WEEKLY,
            report_type="executive_summary",
            content_config={"period": "weekly"},
            recipients=["test@example.com"],
        )
        
        assert report.report_id is not None
        assert report.schedule == ReportSchedule.WEEKLY
    
    def test_generate_report(self, report_automation):
        """Test generating a report."""
        report = report_automation.generate_report(
            report_type="executive_summary",
            content_config={"period": "monthly"},
            format="PDF",
        )
        
        assert "report_id" in report
        assert "content" in report
    
    def test_get_report_schedule(self, report_automation):
        """Test getting report schedule."""
        schedule = report_automation.get_report_schedule()
        
        assert "total_scheduled" in schedule
        assert "by_schedule" in schedule


# =============================================================================
# Integration Tests
# =============================================================================

class TestAnalyticsIntegration:
    """Integration tests for analytics workflow."""
    
    def test_full_analytics_workflow(
        self,
        data_warehouse,
        bi_dashboard,
        advanced_analytics,
        kpi_engine,
        report_automation,
    ):
        """Test full analytics workflow."""
        # 1. Define metric
        metric = data_warehouse.define_metric(
            name="Integration Test",
            description="Test",
            metric_type=MetricType.COUNTER,
            aggregation=AggregationType.SUM,
            category="Test",
            unit="count",
        )
        
        # 2. Record values
        for i in range(10):
            data_warehouse.record_metric_value(
                metric_id=metric.metric_id,
                value=100 + i * 10,
            )
        
        # 3. Analyze trend
        data_points = [100 + i * 10 for i in range(10)]
        now = datetime.now(timezone.utc)
        analysis = advanced_analytics.analyze_trend(
            metric_name="Integration Test",
            data_points=data_points,
            period_start=now - timedelta(days=30),
            period_end=now,
        )
        
        # 4. Create KPI
        kpi = kpi_engine.create_kpi(
            name="Integration KPI",
            description="Test",
            metric_id=metric.metric_id,
            target_value=200.0,
            warning_threshold=150.0,
            critical_threshold=100.0,
            category="Test",
        )
        
        # 5. Create dashboard
        dashboard = bi_dashboard.create_dashboard(
            name="Integration Dashboard",
            description="Test",
        )
        
        # 6. Generate report
        report = report_automation.generate_report(
            report_type="operational_metrics",
            content_config={},
        )
        
        # Verify
        assert metric.metric_id is not None
        assert analysis.analysis_id is not None
        assert kpi.kpi_id is not None
        assert dashboard.dashboard_id is not None
        assert report["report_id"] is not None


# =============================================================================
# Performance Tests
# =============================================================================

class TestAnalyticsPerformance:
    """Performance tests for analytics."""
    
    def test_kpi_update_performance(self, kpi_engine):
        """Test KPI update performance."""
        import time
        
        kpi = kpi_engine.create_kpi(
            name="Performance Test",
            description="Test",
            metric_id="perf_test",
            target_value=100.0,
            warning_threshold=80.0,
            critical_threshold=60.0,
            category="Test",
        )
        
        start = time.time()
        for i in range(100):
            kpi_engine.update_kpi_value(kpi.kpi_id, 100 + i)
        duration = (time.time() - start) * 1000
        
        assert duration < 1000  # 100 updates in under 1 second
    
    def test_trend_analysis_performance(self, advanced_analytics):
        """Test trend analysis performance."""
        import time
        
        data_points = [100 + i * 10 for i in range(100)]
        now = datetime.now(timezone.utc)
        
        start = time.time()
        for _ in range(20):
            advanced_analytics.analyze_trend(
                metric_name="Performance Test",
                data_points=data_points,
                period_start=now - timedelta(days=30),
                period_end=now,
            )
        duration = (time.time() - start) * 1000
        
        assert duration < 2000  # 20 analyses in under 2 seconds