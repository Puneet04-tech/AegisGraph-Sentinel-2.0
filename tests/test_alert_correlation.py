"""Tests for Alert Correlation Module"""
import pytest
from src.alert_correlation import AlertCorrelationService, AlertSeverity

def test_service_init():
    """Test service initialization"""
    service = AlertCorrelationService()
    assert service is not None
    assert len(service.engine.correlation_rules) >= 3

def test_create_alert():
    """Test creating an alert"""
    service = AlertCorrelationService()
    alert = service.create_alert(
        title="Suspicious Login",
        description="Multiple failed login attempts",
        severity="HIGH",
        source="SIEM",
        tags=["authentication", "brute-force"]
    )
    assert alert is not None
    assert alert["title"] == "Suspicious Login"
    assert alert["severity"] == "HIGH"

def test_get_alert():
    """Test getting an alert"""
    service = AlertCorrelationService()
    created = service.create_alert("Get Test", "Desc", "MEDIUM", "EDR")
    retrieved = service.get_alert(created["alert_id"])
    assert retrieved is not None
    assert retrieved["title"] == "Get Test"

def test_get_all_alerts():
    """Test getting all alerts"""
    service = AlertCorrelationService()
    service.create_alert("Alert 1", "Desc", "LOW", "Firewall")
    service.create_alert("Alert 2", "Desc", "HIGH", "EDR")
    alerts = service.get_all_alerts()
    assert len(alerts) >= 2

def test_get_prioritized_alerts():
    """Test getting prioritized alerts"""
    service = AlertCorrelationService()
    service.create_alert("Low Alert", "Desc", "LOW", "Source")
    service.create_alert("Critical Alert", "Desc", "CRITICAL", "Source")
    alerts = service.get_prioritized_alerts()
    assert alerts[0]["severity"] == "CRITICAL"

def test_correlate_alerts():
    """Test correlating alerts"""
    service = AlertCorrelationService()
    a1 = service.create_alert("Alert 1", "Desc", "HIGH", "SIEM")
    a2 = service.create_alert("Alert 2", "Desc", "MEDIUM", "SIEM")
    group = service.correlate_alerts([a1["alert_id"], a2["alert_id"]])
    assert group is not None
    assert len(group["alert_ids"]) == 2

def test_find_duplicates():
    """Test finding duplicates"""
    service = AlertCorrelationService()
    a1 = service.create_alert("Suspicious Activity", "Desc", "HIGH", "SIEM")
    a2 = service.create_alert("Suspicious Activity", "Desc", "MEDIUM", "EDR")
    duplicates = service.find_duplicates(a1["alert_id"])
    assert len(duplicates) >= 1

def test_create_suppression_rule():
    """Test creating suppression rule"""
    service = AlertCorrelationService()
    rule = service.create_suppression_rule(
        name="Test Suppression",
        description="Suppress test alerts",
        conditions={"source": "test"}
    )
    assert rule is not None
    assert rule["name"] == "Test Suppression"

def test_get_suppression_rules():
    """Test getting suppression rules"""
    service = AlertCorrelationService()
    service.create_suppression_rule("Rule 1", "Desc", {"severity": "INFO"})
    rules = service.get_suppression_rules()
    assert len(rules) >= 1

def test_link_to_incident():
    """Test linking alert to incident"""
    service = AlertCorrelationService()
    alert = service.create_alert("Link Test", "Desc", "HIGH", "SIEM")
    result = service.link_to_incident(alert["alert_id"], "INC-001")
    assert result is True

def test_get_dashboard():
    """Test dashboard data"""
    service = AlertCorrelationService()
    service.create_alert("Dashboard Test", "Desc", "MEDIUM", "EDR")
    dashboard = service.get_dashboard()
    assert dashboard is not None
    assert "total_alerts" in dashboard
    assert "alerts_by_severity" in dashboard