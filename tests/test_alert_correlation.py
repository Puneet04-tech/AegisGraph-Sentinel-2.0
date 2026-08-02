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


def test_suppression_rule_multi_condition_and_semantics():
    """Test that multi-condition suppression rules require ALL conditions to match (AND semantics)."""
    service = AlertCorrelationService()
    engine = service.engine

    # 1. Multi-condition AND behavior (one condition matches, one fails -> NOT suppressed)
    engine.create_suppression_rule(
        name="Scanner Noise",
        description="Suppress scanner alerts with LOW severity",
        conditions={"source": "scanner_v2", "severity": "LOW"}
    )
    critical_alert = engine.ingest_alert(
        title="Ransomware Detected",
        description="Breach",
        severity="CRITICAL",
        source="scanner_v2"
    )
    assert engine.should_suppress(critical_alert) is False

    # 2. All conditions satisfied -> Suppressed
    low_alert = engine.ingest_alert(
        title="Port Scan",
        description="Scan",
        severity="LOW",
        source="scanner_v2"
    )
    assert engine.should_suppress(low_alert) is True


def test_suppression_rule_tag_severity_combination():
    """Test tag + severity combination suppression rules."""
    service = AlertCorrelationService()
    engine = service.engine

    engine.create_suppression_rule(
        name="Internal Low Noise",
        description="Suppress internal low alerts",
        conditions={"tag": "internal", "severity": "LOW"}
    )

    # LOW + internal -> suppressed
    a1 = engine.ingest_alert("Low Internal", "Desc", "LOW", "SIEM", tags=["internal"])
    assert engine.should_suppress(a1) is True

    # LOW without tag -> not suppressed
    a2 = engine.ingest_alert("Low External", "Desc", "LOW", "SIEM", tags=["external"])
    assert engine.should_suppress(a2) is False

    # HIGH + internal -> not suppressed
    a3 = engine.ingest_alert("High Internal", "Desc", "HIGH", "SIEM", tags=["internal"])
    assert engine.should_suppress(a3) is False


def test_suppression_rule_single_condition_backwards_compatibility():
    """Test backward compatibility for single-condition suppression rules."""
    service = AlertCorrelationService()
    engine = service.engine

    engine.create_suppression_rule("Single Source", "Desc", conditions={"source": "scanner_v2"})
    engine.create_suppression_rule("Single Severity", "Desc", conditions={"severity": "HIGH"})
    engine.create_suppression_rule("Single Tag", "Desc", conditions={"tag": "phishing"})

    a_src = engine.ingest_alert("Source Alert", "Desc", "INFO", "scanner_v2")
    assert engine.should_suppress(a_src) is True

    a_sev = engine.ingest_alert("Severity Alert", "Desc", "HIGH", "other_source")
    assert engine.should_suppress(a_sev) is True

    a_tag = engine.ingest_alert("Tag Alert", "Desc", "INFO", "other_source", tags=["phishing"])
    assert engine.should_suppress(a_tag) is True


def test_suppression_rule_empty_conditions():
    """Test that empty conditions dictionary does not suppress alerts."""
    service = AlertCorrelationService()
    engine = service.engine

    engine.create_suppression_rule("Empty Rule", "Desc", conditions={})
    alert = engine.ingest_alert("Any Alert", "Desc", "HIGH", "SIEM")
    assert engine.should_suppress(alert) is False



def test_suppression_rule_three_condition_and_semantics():
    """Test 3-condition AND semantics (source + severity + tag)."""
    service = AlertCorrelationService()
    engine = service.engine

    engine.create_suppression_rule(
        name="Three Condition Rule",
        description="Suppress only if source, severity, and tag all match",
        conditions={"source": "scanner_v2", "severity": "LOW", "tag": "internal"}
    )

    # 2 match, 1 fails (tag fails) -> NOT suppressed
    a1 = engine.ingest_alert("Partial Match", "Desc", "LOW", "scanner_v2", tags=["external"])
    assert engine.should_suppress(a1) is False

    # All 3 match -> Suppressed
    a2 = engine.ingest_alert("Full Match", "Desc", "LOW", "scanner_v2", tags=["internal"])
    assert engine.should_suppress(a2) is True


def test_suppression_rule_unknown_condition_key():
    """Test that rules with unrecognized condition keys return False safely."""
    service = AlertCorrelationService()
    engine = service.engine

    engine.create_suppression_rule("Unknown Key Rule", "Desc", conditions={"hostname": "server01"})
    alert = engine.ingest_alert("Any Alert", "Desc", "HIGH", "SIEM")

    assert engine.should_suppress(alert) is False