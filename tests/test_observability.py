"""
Tests for Observability & Platform Health Dashboard.

Comprehensive tests for:
    - Health Monitor
    - Performance Metrics
    - Alert Manager
    - Platform Dashboard
"""

import pytest
from datetime import datetime, timezone

from src.observability import (
    ComponentStatus,
    AlertSeverity,
    AlertStatus,
    ObservabilityStore,
    HealthMonitor,
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