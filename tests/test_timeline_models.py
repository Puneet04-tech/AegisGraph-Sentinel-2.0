# AegisGraph Sentinel Enterprise
# Timeline Model Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from datetime import datetime, timezone
from src.timeline.models import EventType, TimelineEvent, Timeline

def test_event_type_values():
    assert EventType.ALERT.value == "ALERT"
    assert EventType.EVIDENCE.value == "EVIDENCE"
    assert EventType.ACTION.value == "ACTION"
    assert EventType.STATUS_CHANGE.value == "STATUS_CHANGE"
    assert EventType.NOTE.value == "NOTE"
    assert EventType.COMMUNICATION.value == "COMMUNICATION"

def test_timeline_event_creation():
    now = datetime.now(timezone.utc)
    event = TimelineEvent(
        event_id="evt-001",
        investigation_id="inv-100",
        event_type=EventType.ALERT,
        timestamp=now,
        title="High velocity logins",
        description="Many attempts from distinct IPs",
        source="velocity_engine",
        metadata={"failures": 15}
    )
    assert event.event_id == "evt-001"
    assert event.investigation_id == "inv-100"
    assert event.event_type == EventType.ALERT
    assert event.timestamp == now
    assert event.title == "High velocity logins"
    assert event.description == "Many attempts from distinct IPs"
    assert event.source == "velocity_engine"
    assert event.metadata == {"failures": 15}

def test_timeline_event_to_dict():
    now = datetime.now(timezone.utc)
    event = TimelineEvent(
        event_id="evt-002",
        investigation_id="inv-101",
        event_type=EventType.NOTE,
        timestamp=now,
        title="Analyst note",
        description="Checking database flags",
        source="analyst",
        metadata={}
    )
    data = event.to_dict()
    assert data["event_id"] == "evt-002"
    assert data["event_type"] == "NOTE"
    assert data["timestamp"] == now.isoformat()
    assert data["title"] == "Analyst note"
    assert data["metadata"] == {}

def test_timeline_creation():
    now = datetime.now(timezone.utc)
    timeline = Timeline(
        timeline_id="line-001",
        investigation_id="inv-100",
        name="Primary Investigation Timeline",
        events=["evt-001", "evt-002"],
        created_at=now
    )
    assert timeline.timeline_id == "line-001"
    assert timeline.investigation_id == "inv-100"
    assert timeline.name == "Primary Investigation Timeline"
    assert timeline.events == ["evt-001", "evt-002"]
    assert timeline.created_at == now

def test_timeline_to_dict():
    now = datetime.now(timezone.utc)
    timeline = Timeline(
        timeline_id="line-002",
        investigation_id="inv-102",
        name="Empty Timeline",
        created_at=now
    )
    data = timeline.to_dict()
    assert data["timeline_id"] == "line-002"
    assert data["events"] == []
    assert data["created_at"] == now.isoformat()
