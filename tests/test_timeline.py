"""Tests for Timeline Module"""
import pytest
from src.timeline import TimelineService

def test_create_timeline():
    service = TimelineService()
    timeline = service.create_timeline("INV-001", "Investigation Timeline")
    assert timeline is not None
    assert timeline["name"] == "Investigation Timeline"

def test_add_event():
    service = TimelineService()
    service.create_timeline("INV-001", "Test")
    event = service.add_event("INV-001", "ALERT", "Suspicious Login", "Failed login attempts", "SIEM")
    assert event is not None
    assert event["title"] == "Suspicious Login"

def test_get_timeline_events():
    service = TimelineService()
    timeline = service.create_timeline("INV-001", "Test")
    service.add_event("INV-001", "ALERT", "Event 1", "Desc", "Source")
    service.add_event("INV-001", "EVIDENCE", "Event 2", "Desc", "Source")
    events = service.get_timeline_events(timeline["timeline_id"])
    assert isinstance(events, list)
    assert len(events) == 2
    assert events[0]["title"] == "Event 1"
    assert events[1]["title"] == "Event 2"

def test_get_dashboard():
    service = TimelineService()
    service.create_timeline("INV-001", "Test")
    service.add_event("INV-001", "ALERT", "Event", "Desc", "Source")
    dashboard = service.get_dashboard()
    assert "total_events" in dashboard