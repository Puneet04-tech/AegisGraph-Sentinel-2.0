"""Tests for Patterns Module"""
import pytest
from src.patterns import FraudPatternService

def test_service_init():
    service = FraudPatternService()
    assert service is not None
    assert len(service.patterns) >= 2

def test_create_pattern():
    service = FraudPatternService()
    pattern = service.create_pattern(
        name="Test Pattern",
        pattern_type="BEHAVIORAL",
        description="Test description",
        rules=[{"type": "test"}],
        severity="HIGH"
    )
    assert pattern is not None
    assert pattern["name"] == "Test Pattern"

def test_detect():
    service = FraudPatternService()
    detection = service.detect("pat-001", "entity-123", {"amount": 5000})
    assert detection is not None
    assert detection["confidence"] == 0.7

def test_get_detections():
    service = FraudPatternService()
    service.detect("pat-001", "entity-1", {})
    detections = service.get_detections()
    assert len(detections) >= 1

def test_update_status():
    service = FraudPatternService()
    detection = service.detect("pat-001", "entity-2", {})
    updated = service.update_detection_status(detection["detection_id"], "CONFIRMED")
    assert updated is not None

def test_get_dashboard():
    service = FraudPatternService()
    service.detect("pat-001", "entity-3", {})
    dashboard = service.get_dashboard()
    assert "total_detections" in dashboard