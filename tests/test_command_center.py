"""Tests for Command Center Module"""
import pytest
from src.command_center import CommandCenterService

def test_service_init():
    service = CommandCenterService()
    assert service is not None
    assert len(service.metrics) >= 2

def test_record_metric():
    service = CommandCenterService()
    metric = service.record_metric("SECURITY", "Test Metric", 100.0, "count")
    assert metric is not None
    assert metric["value"] == 100.0

def test_add_threat():
    service = CommandCenterService()
    threat = service.add_threat(
        title="Test Threat",
        severity="HIGH",
        source="SIEM",
        description="Test description"
    )
    assert threat is not None
    assert threat["severity"] == "HIGH"

def test_get_active_threats():
    service = CommandCenterService()
    service.add_threat("Threat 1", "MEDIUM", "EDR", "Desc")
    threats = service.get_active_threats()
    assert len(threats) >= 1

def test_create_dashboard():
    service = CommandCenterService()
    dashboard = service.create_dashboard(
        name="Test Dashboard",
        widgets=[{"type": "chart", "title": "Threats"}]
    )
    assert dashboard is not None
    assert dashboard["name"] == "Test Dashboard"

def test_get_command_center_dashboard():
    service = CommandCenterService()
    service.add_threat("Threat", "HIGH", "Source", "Desc")
    dashboard = service.get_command_center_dashboard()
    assert dashboard is not None
    assert "threat_level" in dashboard
    assert "active_threats" in dashboard