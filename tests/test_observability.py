"""
Tests for Observability & Platform Health Dashboard.

Comprehensive tests for:
    - Health Monitor
    - Performance Metrics
    - Alert Manager
    - Platform Dashboard
"""

import pytest
from datetime import datetime, timedelta, timezone

from src.observability import (
    ComponentStatus,
    AlertSeverity,
    AlertStatus,
    ObservabilityStore,
    HealthMonitor,
    PerformanceMetric,
    PerformanceTracker,
    AlertManager,
    PlatformDashboard,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def store():
    """Create a fresh observability store for testing."""
    return ObservabilityStore(max_metrics=100)


@pytest.fixture
def health_monitor(store):
    """Create a health monitor."""
    return HealthMonitor(store=store)


@pytest.fixture
def performance_tracker(store):
    """Create a performance tracker."""
    return PerformanceTracker(store=store)


@pytest.fixture
def alert_manager(store):
    """Create an alert manager."""
    return AlertManager(store=store)


@pytest.fixture
def dashboard(store):
    """Create a platform dashboard."""
    return PlatformDashboard(store=store)


# =============================================================================
# Store Tests
# =============================================================================

class TestObservabilityStore:
    """Tests for ObservabilityStore."""
    
    def test_get_stats(self, store):
        """Test getting store statistics."""
        stats = store.get_stats()
        
        assert "components_monitored" in stats
        assert "metrics_stored" in stats
        assert "active_alerts" in stats
    
    def test_health_summary(self, store):
        """Test getting health summary."""
        summary = store.get_health_summary()
        
        assert "total_components" in summary
        assert "average_health_score" in summary


# =============================================================================
# Health Monitor Tests
# =============================================================================

class TestHealthMonitor:
    """Tests for HealthMonitor."""
    
    def test_register_component(self, health_monitor):
        """Test registering a component."""
        component = health_monitor.register_component(
            component_name="Test Service",
            component_type="api",
        )
        
        assert component.component_id is not None
        assert component.component_name == "Test Service"
    
    def test_check_health(self, health_monitor):
        """Test health check."""
        component = health_monitor.register_component(
            component_name="Health Check Test",
            component_type="database",
        )
        
        result = health_monitor.check_health(component.component_id)
        
        assert "status" in result
        assert "health_score" in result
    
    def test_get_health_summary(self, health_monitor):
        """Test getting health summary."""
        summary = health_monitor.get_health_summary()
        
        assert "total_components" in summary
        assert summary["total_components"] >= 1
    
    def test_calculate_overall_health(self, health_monitor):
        """Test calculating overall health."""
        score = health_monitor.calculate_overall_health()
        
        assert 0 <= score <= 100


# =============================================================================
# Performance Tracker Tests
# =============================================================================

class TestPerformanceTracker:
    """Tests for PerformanceTracker."""
    
    def test_record_metric(self, performance_tracker):
        """Test recording a metric."""
        metric = performance_tracker.record_metric(
            metric_name="test_metric",
            component="api",
            value=100.0,
            unit="ms",
        )
        
        assert metric.metric_id is not None
    
    def test_record_latency(self, performance_tracker):
        """Test recording latency."""
        metric = performance_tracker.record_request_latency(
            component="api",
            endpoint="/test",
            latency_ms=50.0,
        )
        
        assert metric.metric_name == "latency_ms"
    
    def test_get_latency_stats(self, performance_tracker):
        """Test getting latency statistics."""
        # Record some metrics
        for i in range(10):
            performance_tracker.record_metric(
                metric_name="latency_ms",
                component="test_component",
                value=50.0 + i * 5,
                unit="ms",
            )
        
        stats = performance_tracker.get_latency_stats("test_component")
        
        assert "min" in stats
        assert "max" in stats
        assert "p95" in stats
    
    def test_get_performance_summary(self, performance_tracker):
        """Test getting performance summary."""
        summary = performance_tracker.get_performance_summary()
        
        assert "overall_health" in summary
        assert "components" in summary

    def test_get_throughput_stats_empty(self, performance_tracker):
        """Throughput is zero when no metrics exist."""
        stats = performance_tracker.get_throughput_stats("empty_component")

        assert stats["requests_last_hour"] == 0
        assert stats["avg_per_second"] == 0

    def test_get_throughput_stats_sums_recent_requests(self, performance_tracker):
        """Throughput sums request values within the last hour."""
        performance_tracker.record_throughput(component="api", count=100)
        performance_tracker.record_throughput(component="api", count=200)

        stats = performance_tracker.get_throughput_stats("api")

        assert stats["requests_last_hour"] == 300
        assert stats["avg_per_second"] == pytest.approx(300 / 3600)

    def test_get_throughput_stats_is_component_scoped(self, performance_tracker):
        """Requests recorded for one component do not leak into another."""
        performance_tracker.record_throughput(component="api", count=100)
        performance_tracker.record_throughput(component="worker", count=900)

        stats = performance_tracker.get_throughput_stats("api")

        assert stats["requests_last_hour"] == 100

    def test_get_throughput_stats_window_is_volume_independent(self):
        """Throughput aggregates the full hour window, not a truncated set."""
        store = ObservabilityStore(max_metrics=5000)
        tracker = PerformanceTracker(store=store)
        now = datetime.now(timezone.utc)

        # 1200 in-window request records (value 1 each) — more than the old
        # 1000-record cap — plus stale records outside the window with much
        # larger values that must be excluded.
        for _ in range(1200):
            store.store_metric(
                PerformanceMetric(
                    metric_name="requests",
                    component="api",
                    value=1.0,
                    unit="count",
                    timestamp=now - timedelta(minutes=30),
                )
            )
        for _ in range(200):
            store.store_metric(
                PerformanceMetric(
                    metric_name="requests",
                    component="api",
                    value=100.0,
                    unit="count",
                    timestamp=now - timedelta(hours=2),
                )
            )

        stats = tracker.get_throughput_stats("api")

        assert stats["requests_last_hour"] == 1200
        assert stats["avg_per_second"] == pytest.approx(1200 / 3600)

    def test_get_latency_stats_exact_percentiles(self, performance_tracker):
        """Percentiles are computed from sorted values."""
        for i in range(100):
            performance_tracker.record_request_latency(
                component="api", endpoint="/v1/score", latency_ms=float(i)
            )

        stats = performance_tracker.get_latency_stats("api")

        assert stats["count"] == 100
        assert stats["min"] == 0
        assert stats["max"] == 99
        assert stats["avg"] == pytest.approx(49.5)
        assert stats["p50"] == 50
        assert stats["p95"] == 95
        assert stats["p99"] == 99

    def test_get_latency_stats_no_metrics(self, performance_tracker):
        """Latency stats report an error when no metrics exist."""
        stats = performance_tracker.get_latency_stats("empty_component")
        assert "error" in stats

    def test_get_latency_stats_uses_full_distribution(self):
        """Percentiles use all latency samples, not only the newest 1000."""
        store = ObservabilityStore(max_metrics=5000)
        tracker = PerformanceTracker(store=store)
        for i in range(1500):
            tracker.record_request_latency(
                component="api", endpoint="/v1/score", latency_ms=float(i)
            )

        stats = tracker.get_latency_stats("api")

        assert stats["count"] == 1500
        assert stats["min"] == 0
        assert stats["max"] == 1499
        assert stats["p50"] == 750

    def test_record_metric_stores_tags(self, performance_tracker):
        """Tags recorded with a metric are retrievable through get_metrics."""
        performance_tracker.record_metric(
            metric_name="latency_ms",
            component="api",
            value=12.5,
            unit="ms",
            tags={"endpoint": "/v1/score", "region": "ap-south"},
        )

        metrics = performance_tracker.get_metrics(component="api", metric_name="latency_ms")
        assert len(metrics) == 1
        assert metrics[0].tags["endpoint"] == "/v1/score"
        assert metrics[0].tags["region"] == "ap-south"

    def test_get_metrics_honors_limit(self, performance_tracker):
        """get_metrics limits the number of returned records."""
        for i in range(25):
            performance_tracker.record_metric(
                metric_name="latency_ms",
                component="api",
                value=float(i),
                unit="ms",
            )

        metrics = performance_tracker.get_metrics(component="api", limit=10)

        assert len(metrics) == 10

    def test_get_metrics_since_bounds_window_before_truncation(self, store):
        """get_metrics applies the since window before the limit truncation."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        store.store_metric(
            PerformanceMetric(
                metric_name="requests", component="api", value=1.0, unit="count",
                timestamp=base,
            )
        )
        store.store_metric(
            PerformanceMetric(
                metric_name="requests", component="api", value=2.0, unit="count",
                timestamp=base + timedelta(hours=2),
            )
        )

        metrics = store.get_metrics(component="api", since=base + timedelta(hours=1))

        assert len(metrics) == 1
        assert metrics[0].value == 2.0

    def test_get_error_rate_no_metrics(self, performance_tracker):
        """Error rate is zero when no metrics recorded."""
        stats = performance_tracker.get_error_rate("empty_component")

        assert stats["total_requests"] == 0
        assert stats["errors"] == 0
        assert stats["error_rate_percent"] == 0

    def test_get_error_rate_single_batch(self, performance_tracker):
        """Error rate uses summed request values, not record counts."""
        performance_tracker.record_throughput(component="api", count=1000)
        performance_tracker.record_errors(component="api", count=50)

        stats = performance_tracker.get_error_rate("api")

        assert stats["total_requests"] == 1000
        assert stats["errors"] == 50
        assert stats["error_rate_percent"] == 5.0

    def test_get_error_rate_multiple_batches(self, performance_tracker):
        """Error rate sums requests across multiple throughput records."""
        performance_tracker.record_throughput(component="api", count=400)
        performance_tracker.record_throughput(component="api", count=600)
        performance_tracker.record_errors(component="api", count=20)

        stats = performance_tracker.get_error_rate("api")

        assert stats["total_requests"] == 1000
        assert stats["error_rate_percent"] == 2.0

    def test_get_error_rate_no_errors(self, performance_tracker):
        """Error rate is zero when requests succeed."""
        performance_tracker.record_throughput(component="api", count=500)

        stats = performance_tracker.get_error_rate("api")

        assert stats["errors"] == 0
        assert stats["error_rate_percent"] == 0

    def test_get_error_rate_errors_without_requests(self, performance_tracker):
        """Error rate is zero when there are no request metrics."""
        performance_tracker.record_errors(component="api", count=10)

        stats = performance_tracker.get_error_rate("api")

        assert stats["total_requests"] == 0
        assert stats["error_rate_percent"] == 0

    def test_get_error_rate_component_isolation(self, performance_tracker):
        """Errors in one component do not affect another component's rate."""
        performance_tracker.record_throughput(component="api", count=1000)
        performance_tracker.record_errors(component="api", count=10)
        performance_tracker.record_errors(component="worker", count=900)

        stats = performance_tracker.get_error_rate("api")

        assert stats["errors"] == 10
        assert stats["error_rate_percent"] == 1.0

    def test_get_error_rate_volume_independent(self):
        """Error rate uses complete per-metric pools, not a truncated mix."""
        store = ObservabilityStore(max_metrics=5000)
        tracker = PerformanceTracker(store=store)

        # Errors are older than the requests, so a newest-1000 truncation
        # would drop them entirely and report a 0% rate.
        for _ in range(300):
            tracker.record_errors(component="api", count=1)
        for _ in range(1000):
            tracker.record_throughput(component="api", count=1)

        stats = tracker.get_error_rate("api")

        assert stats["total_requests"] == 1000
        assert stats["errors"] == 300
        assert stats["error_rate_percent"] == pytest.approx(30.0)


# =============================================================================
# Alert Manager Tests
# =============================================================================

class TestAlertManager:
    """Tests for AlertManager."""
    
    def test_create_rule(self, alert_manager):
        """Test creating an alert rule."""
        rule = alert_manager.create_rule(
            name="High Latency",
            description="Alert when latency is high",
            condition={"metric": "latency_ms", "threshold": 100, "operator": "gt"},
            severity=AlertSeverity.HIGH,
        )
        
        assert rule.rule_id is not None
    
    def test_enable_disable_rule(self, alert_manager):
        """Test enabling and disabling rules."""
        rule = alert_manager.create_rule(
            name="Test Rule",
            description="Test",
            condition={},
            severity=AlertSeverity.MEDIUM,
        )
        
        rule = alert_manager.disable_rule(rule.rule_id)
        assert rule.enabled is False
        
        rule = alert_manager.enable_rule(rule.rule_id)
        assert rule.enabled is True
    
    def test_create_alert(self, alert_manager):
        """Test creating an alert."""
        alert = alert_manager.create_alert(
            title="Test Alert",
            description="Test alert description",
            severity=AlertSeverity.HIGH,
            component="api",
        )
        
        assert alert.alert_id is not None
    
    def test_acknowledge_alert(self, alert_manager):
        """Test acknowledging an alert."""
        alert = alert_manager.create_alert(
            title="Ack Test",
            description="Test",
            severity=AlertSeverity.MEDIUM,
            component="api",
        )
        
        acknowledged = alert_manager.acknowledge_alert(alert.alert_id, "analyst1")
        
        assert acknowledged.status == AlertStatus.ACKNOWLEDGED
    
    def test_resolve_alert(self, alert_manager):
        """Test resolving an alert."""
        alert = alert_manager.create_alert(
            title="Resolve Test",
            description="Test",
            severity=AlertSeverity.LOW,
            component="database",
        )
        
        resolved = alert_manager.resolve_alert(alert.alert_id)
        
        assert resolved.status == AlertStatus.RESOLVED
    
    def test_get_active_alerts(self, alert_manager):
        """Test getting active alerts."""
        alert_manager.create_alert(
            title="Active Test 1",
            description="Test",
            severity=AlertSeverity.HIGH,
            component="api",
        )
        
        alerts = alert_manager.get_active_alerts()
        
        assert isinstance(alerts, list)


# =============================================================================
# Dashboard Tests
# =============================================================================

class TestDashboard:
    """Tests for PlatformDashboard."""
    
    def test_get_dashboard_data(self, dashboard):
        """Test getting dashboard data."""
        data = dashboard.get_dashboard_data()
        
        assert "timestamp" in data
        assert "overall_health_score" in data
        assert "health" in data
        assert "alerts" in data
    
    def test_create_incident(self, dashboard):
        """Test creating an incident."""
        incident = dashboard.create_incident(
            title="Test Incident",
            description="Test incident description",
            severity=AlertSeverity.HIGH,
            affected_components=["api", "database"],
        )
        
        assert incident.incident_id is not None
    
    def test_update_incident_status(self, dashboard):
        """Test updating incident status."""
        incident = dashboard.create_incident(
            title="Status Test",
            description="Test",
            severity=AlertSeverity.MEDIUM,
        )
        
        updated = dashboard.update_incident_status(incident.incident_id, "INVESTIGATING")
        
        assert updated.status == "INVESTIGATING"
    
    def test_log_audit(self, dashboard):
        """Test logging audit entry."""
        entry = dashboard.log_audit(
            action="test_action",
            resource_type="test_resource",
            user="test_user",
            details={"key": "value"},
        )
        
        assert entry.entry_id is not None
    
    def test_get_audit_trail(self, dashboard):
        """Test getting audit trail."""
        dashboard.log_audit(
            action="test_audit",
            resource_type="test",
        )
        
        trail = dashboard.get_audit_trail()
        
        assert isinstance(trail, list)
    
    def test_get_compliance_report(self, dashboard):
        """Test getting compliance report."""
        report = dashboard.get_compliance_report()
        
        assert "report_date" in report
        assert "total_audit_entries" in report

    def test_dynamic_telemetry_in_snapshot(self, store, dashboard, performance_tracker):
        """Test that dashboard snapshots record dynamic request and latency telemetry."""
        # Initial snapshot with no metrics recorded
        d1 = dashboard.get_dashboard_data()
        s1 = store.get_latest_snapshot()
        assert s1.total_requests == 0
        assert s1.avg_response_time_ms == 0.0

        # Record metrics
        performance_tracker.record_throughput("api", 250)
        performance_tracker.record_request_latency("api", "/v1/test", 120.0)
        performance_tracker.record_request_latency("api", "/v1/test", 180.0)

        d2 = dashboard.get_dashboard_data()
        s2 = store.get_latest_snapshot()

        assert s2.total_requests == 250
        assert s2.avg_response_time_ms == 150.0
        assert d2["total_requests"] == 250
        assert d2["avg_response_time_ms"] == 150.0



# =============================================================================
# Integration Tests
# =============================================================================

class TestObservabilityIntegration:
    """Integration tests for observability workflow."""
    
    def test_full_observability_workflow(
        self,
        health_monitor,
        performance_tracker,
        alert_manager,
        dashboard,
    ):
        """Test full observability workflow."""
        # 1. Register component
        component = health_monitor.register_component(
            component_name="Integration Service",
            component_type="api",
        )
        
        # 2. Check health
        health_monitor.check_health(component.component_id)
        
        # 3. Record metrics
        performance_tracker.record_request_latency(
            component="integration_service",
            endpoint="/api/test",
            latency_ms=75.0,
        )
        
        # 4. Create alert rule
        rule = alert_manager.create_rule(
            name="High Latency Alert",
            description="Alert when latency exceeds threshold",
            condition={"metric": "latency_ms", "threshold": 100, "operator": "gt"},
            severity=AlertSeverity.HIGH,
        )
        
        # 5. Create alert
        alert = alert_manager.create_alert(
            title="Integration Test Alert",
            description="Test alert from integration workflow",
            severity=AlertSeverity.HIGH,
            component="integration_service",
        )
        
        # 6. Create incident
        incident = dashboard.create_incident(
            title="Integration Incident",
            description="Test incident",
            severity=AlertSeverity.MEDIUM,
            affected_components=["integration_service"],
        )
        
        # 7. Log audit
        dashboard.log_audit(
            action="integration_test",
            resource_type="test",
            details={"component_id": component.component_id},
        )
        
        # 8. Get dashboard
        dashboard_data = dashboard.get_dashboard_data()
        
        # Verify
        assert component.component_id is not None
        assert rule.rule_id is not None
        assert alert.alert_id is not None
        assert incident.incident_id is not None
        assert "overall_health_score" in dashboard_data