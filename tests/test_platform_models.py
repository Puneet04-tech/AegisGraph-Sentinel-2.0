"""Tests for model dataclasses/enums across platform modules."""
import json

import pytest
from datetime import datetime, timezone

from src.playbooks.models import Execution, ExecutionStatus, Playbook, PlaybookTask, TaskStatus
from src.command_center.models import (
    DashboardConfig,
    MetricType,
    SecurityMetric,
    ThreatEvent,
    ThreatLevel,
)
from src.watchlist.models import (
    MatchResult,
    ScreeningResult,
    WatchlistEntry,
    WatchlistType,
)
from src.timeline.models import EventType, Timeline, TimelineEvent


class TestExecutionStatus:
    def test_all_values(self):
        assert ExecutionStatus.PENDING.value == "PENDING"
        assert ExecutionStatus.RUNNING.value == "RUNNING"
        assert ExecutionStatus.COMPLETED.value == "COMPLETED"
        assert ExecutionStatus.FAILED.value == "FAILED"
        assert ExecutionStatus.CANCELLED.value == "CANCELLED"

    def test_membership(self):
        assert {s.value for s in ExecutionStatus} == {
            "PENDING",
            "RUNNING",
            "COMPLETED",
            "FAILED",
            "CANCELLED",
        }


class TestTaskStatus:
    def test_all_values(self):
        assert TaskStatus.PENDING.value == "PENDING"
        assert TaskStatus.IN_PROGRESS.value == "IN_PROGRESS"
        assert TaskStatus.COMPLETED.value == "COMPLETED"
        assert TaskStatus.SKIPPED.value == "SKIPPED"
        assert TaskStatus.FAILED.value == "FAILED"


class TestPlaybookTask:
    def test_to_dict(self):
        task = PlaybookTask(
            task_id="t-1",
            name="Block IP",
            action_type="network.block",
            parameters={"ip": "1.2.3.4"},
            order=2,
            requires_approval=True,
            retry_count=3,
        )
        assert task.to_dict() == {
            "task_id": "t-1",
            "name": "Block IP",
            "action_type": "network.block",
            "parameters": {"ip": "1.2.3.4"},
            "order": 2,
            "requires_approval": True,
            "retry_count": 3,
        }

    def test_defaults(self):
        task = PlaybookTask(
            task_id="t-2", name="Notify", action_type="notify.slack", parameters={}, order=1
        )
        assert task.requires_approval is False
        assert task.retry_count == 0
        assert task.to_dict()["requires_approval"] is False
        assert task.to_dict()["retry_count"] == 0

    def test_round_trip(self):
        task = PlaybookTask(
            task_id="t-3",
            name="Contain",
            action_type="endpoint.isolate",
            parameters={"host": "srv-01"},
            order=4,
        )
        rebuilt = PlaybookTask(**task.to_dict())
        assert rebuilt == task
        assert rebuilt.to_dict() == task.to_dict()


class TestPlaybook:
    def test_to_dict(self):
        task = PlaybookTask(
            task_id="t-1", name="Block IP", action_type="network.block", parameters={}, order=1
        )
        playbook = Playbook(
            playbook_id="pb-1",
            name="Ransomware Response",
            description="Automated containment",
            trigger_type="alert",
            tasks=[task],
            enabled=False,
            created_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        )
        d = playbook.to_dict()
        assert d["playbook_id"] == "pb-1"
        assert d["name"] == "Ransomware Response"
        assert d["description"] == "Automated containment"
        assert d["trigger_type"] == "alert"
        assert d["tasks"] == [task.to_dict()]
        assert d["enabled"] is False
        assert d["created_at"] == "2026-01-02T03:04:05+00:00"

    def test_default_enabled_and_datetime(self):
        playbook = Playbook(
            playbook_id="pb-2",
            name="Phishing Triage",
            description="Triage flow",
            trigger_type="email",
            tasks=[],
        )
        assert playbook.enabled is True
        assert isinstance(playbook.created_at, datetime)

    def test_empty_tasks(self):
        playbook = Playbook(
            playbook_id="pb-3",
            name="No tasks",
            description="",
            trigger_type="manual",
            tasks=[],
        )
        assert playbook.to_dict()["tasks"] == []

    def test_json_round_trip(self):
        task = PlaybookTask(
            task_id="t-1", name="Quarantine", action_type="email.quarantine", parameters={}, order=1
        )
        playbook = Playbook(
            playbook_id="pb-4",
            name="Quarantine Flow",
            description="desc",
            trigger_type="event",
            tasks=[task],
            created_at=datetime(2026, 7, 8, 9, 10, 11, tzinfo=timezone.utc),
        )
        assert json.loads(json.dumps(playbook.to_dict())) == playbook.to_dict()
        assert playbook.to_dict()["tasks"] == [task.to_dict()]


class TestExecution:
    def test_to_dict(self):
        exec_obj = Execution(
            execution_id="e-1",
            playbook_id="pb-1",
            status=ExecutionStatus.RUNNING,
            started_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 1, 1, 0, 0, tzinfo=timezone.utc),
            current_task="t-2",
            results=[{"task_id": "t-1", "ok": True}],
        )
        d = exec_obj.to_dict()
        assert d["execution_id"] == "e-1"
        assert d["playbook_id"] == "pb-1"
        assert d["status"] == "RUNNING"
        assert d["started_at"] == "2026-01-01T00:00:00+00:00"
        assert d["completed_at"] == "2026-01-01T01:00:00+00:00"
        assert d["current_task"] == "t-2"
        assert d["results"] == [{"task_id": "t-1", "ok": True}]

    def test_optional_none_fields(self):
        exec_obj = Execution(
            execution_id="e-2",
            playbook_id="pb-1",
            status=ExecutionStatus.PENDING,
            started_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        )
        assert exec_obj.completed_at is None
        assert exec_obj.current_task is None
        assert exec_obj.results == []
        d = exec_obj.to_dict()
        assert d["completed_at"] is None
        assert d["current_task"] is None
        assert d["results"] == []

    def test_json_round_trip(self):
        exec_obj = Execution(
            execution_id="e-3",
            playbook_id="pb-2",
            status=ExecutionStatus.FAILED,
            started_at=datetime(2026, 2, 2, 2, 2, 2, tzinfo=timezone.utc),
            completed_at=None,
            current_task="t-9",
            results=[{"step": 1}],
        )
        assert json.loads(json.dumps(exec_obj.to_dict())) == exec_obj.to_dict()
        assert exec_obj.to_dict()["status"] == "FAILED"


class TestMetricType:
    def test_all_values(self):
        assert MetricType.SECURITY.value == "SECURITY"
        assert MetricType.FRAUD.value == "FRAUD"
        assert MetricType.OPERATIONAL.value == "OPERATIONAL"
        assert MetricType.COMPLIANCE.value == "COMPLIANCE"


class TestThreatLevel:
    def test_all_values(self):
        assert ThreatLevel.GREEN.value == "GREEN"
        assert ThreatLevel.YELLOW.value == "YELLOW"
        assert ThreatLevel.ORANGE.value == "ORANGE"
        assert ThreatLevel.RED.value == "RED"


class TestSecurityMetric:
    def test_to_dict(self):
        metric = SecurityMetric(
            metric_id="m-1",
            metric_type=MetricType.FRAUD,
            name="mule_accounts",
            value=12.5,
            unit="count",
            timestamp=datetime(2026, 3, 3, 3, 3, 3, tzinfo=timezone.utc),
        )
        d = metric.to_dict()
        assert d["metric_id"] == "m-1"
        assert d["metric_type"] == "FRAUD"
        assert d["name"] == "mule_accounts"
        assert d["value"] == 12.5
        assert d["unit"] == "count"
        assert d["timestamp"] == "2026-03-03T03:03:03+00:00"

    def test_default_timestamp(self):
        metric = SecurityMetric(
            metric_id="m-2",
            metric_type=MetricType.SECURITY,
            name="alerts",
            value=0.0,
            unit="count",
        )
        assert isinstance(metric.timestamp, datetime)

    def test_json_round_trip(self):
        metric = SecurityMetric(
            metric_id="m-3",
            metric_type=MetricType.COMPLIANCE,
            name="score",
            value=99.9,
            unit="pct",
            timestamp=datetime(2026, 4, 4, 4, 4, 4, tzinfo=timezone.utc),
        )
        assert json.loads(json.dumps(metric.to_dict())) == metric.to_dict()
        assert metric.to_dict()["metric_type"] == "COMPLIANCE"


class TestThreatEvent:
    def test_to_dict(self):
        event = ThreatEvent(
            event_id="ev-1",
            title="Suspicious Transfer",
            severity="HIGH",
            source="screening",
            description="Large transfer detected",
            timestamp=datetime(2026, 5, 5, 5, 5, 5, tzinfo=timezone.utc),
        )
        d = event.to_dict()
        assert d["event_id"] == "ev-1"
        assert d["title"] == "Suspicious Transfer"
        assert d["severity"] == "HIGH"
        assert d["source"] == "screening"
        assert d["description"] == "Large transfer detected"
        assert d["timestamp"] == "2026-05-05T05:05:05+00:00"

    def test_json_round_trip(self):
        event = ThreatEvent(
            event_id="ev-2",
            title="T",
            severity="LOW",
            source="s",
            description="d",
            timestamp=datetime(2026, 6, 6, 6, 6, 6, tzinfo=timezone.utc),
        )
        assert json.loads(json.dumps(event.to_dict())) == event.to_dict()
        assert event.to_dict()["timestamp"] == "2026-06-06T06:06:06+00:00"


class TestDashboardConfig:
    def test_to_dict(self):
        config = DashboardConfig(
            config_id="c-1",
            name="Executive Overview",
            widgets=[{"id": "w1", "type": "chart"}],
            refresh_interval=30,
        )
        assert config.to_dict() == {
            "config_id": "c-1",
            "name": "Executive Overview",
            "widgets": [{"id": "w1", "type": "chart"}],
            "refresh_interval": 30,
        }

    def test_default_refresh_interval(self):
        config = DashboardConfig(config_id="c-2", name="Ops", widgets=[])
        assert config.refresh_interval == 60

    def test_empty_widgets(self):
        config = DashboardConfig(config_id="c-3", name="Empty", widgets=[])
        assert config.to_dict()["widgets"] == []

    def test_round_trip(self):
        config = DashboardConfig(
            config_id="c-4",
            name="SOC",
            widgets=[{"id": "a"}, {"id": "b"}],
            refresh_interval=15,
        )
        rebuilt = DashboardConfig(**config.to_dict())
        assert rebuilt == config
        assert rebuilt.to_dict() == config.to_dict()


class TestWatchlistType:
    def test_all_values(self):
        assert WatchlistType.SANCTIONS.value == "SANCTIONS"
        assert WatchlistType.PEP.value == "PEP"
        assert WatchlistType.ADVERSE_MEDIA.value == "ADVERSE_MEDIA"
        assert WatchlistType.CUSTOM.value == "CUSTOM"


class TestMatchResult:
    def test_all_values(self):
        assert MatchResult.NO_MATCH.value == "NO_MATCH"
        assert MatchResult.POTENTIAL_MATCH.value == "POTENTIAL_MATCH"
        assert MatchResult.CONFIRMED_MATCH.value == "CONFIRMED_MATCH"


class TestWatchlistEntry:
    def test_to_dict(self):
        entry = WatchlistEntry(
            entry_id="wl-1",
            watchlist_type=WatchlistType.PEP,
            name="John Doe",
            aliases=["J. Doe", "Jonathan Doe"],
            identifiers={"passport": "X123"},
            risk_score=0.9,
            source="gov",
        )
        d = entry.to_dict()
        assert d["entry_id"] == "wl-1"
        assert d["watchlist_type"] == "PEP"
        assert d["name"] == "John Doe"
        assert d["aliases"] == ["J. Doe", "Jonathan Doe"]
        assert d["identifiers"] == {"passport": "X123"}
        assert d["risk_score"] == 0.9
        assert d["source"] == "gov"

    def test_defaults(self):
        entry = WatchlistEntry(entry_id="wl-2", watchlist_type=WatchlistType.CUSTOM, name="Entity")
        assert entry.aliases == []
        assert entry.identifiers == {}
        assert entry.risk_score == 0.5
        assert entry.source == ""

    def test_empty_collections(self):
        entry = WatchlistEntry(
            entry_id="wl-3", watchlist_type=WatchlistType.SANCTIONS, name="Listed"
        )
        d = entry.to_dict()
        assert d["aliases"] == []
        assert d["identifiers"] == {}

    def test_json_round_trip(self):
        entry = WatchlistEntry(
            entry_id="wl-4",
            watchlist_type=WatchlistType.ADVERSE_MEDIA,
            name="ACME Corp",
            aliases=["ACME"],
            identifiers={"lei": "L-1"},
            risk_score=0.25,
            source="news",
        )
        assert json.loads(json.dumps(entry.to_dict())) == entry.to_dict()
        assert entry.to_dict()["watchlist_type"] == "ADVERSE_MEDIA"


class TestScreeningResult:
    def test_to_dict(self):
        result = ScreeningResult(
            result_id="r-1",
            entity_name="Jane Roe",
            entity_id="ent-1",
            match_result=MatchResult.CONFIRMED_MATCH,
            matched_entry_id="wl-1",
            confidence=0.99,
            screened_at=datetime(2026, 7, 7, 7, 7, 7, tzinfo=timezone.utc),
        )
        d = result.to_dict()
        assert d["result_id"] == "r-1"
        assert d["entity_name"] == "Jane Roe"
        assert d["entity_id"] == "ent-1"
        assert d["match_result"] == "CONFIRMED_MATCH"
        assert d["matched_entry_id"] == "wl-1"
        assert d["confidence"] == 0.99
        assert d["screened_at"] == "2026-07-07T07:07:07+00:00"

    def test_none_matched_entry(self):
        result = ScreeningResult(
            result_id="r-2",
            entity_name="Unknown",
            entity_id="ent-2",
            match_result=MatchResult.NO_MATCH,
            matched_entry_id=None,
            confidence=0.0,
        )
        assert result.to_dict()["matched_entry_id"] is None
        assert result.to_dict()["match_result"] == "NO_MATCH"

    def test_json_round_trip(self):
        result = ScreeningResult(
            result_id="r-3",
            entity_name="Bob",
            entity_id="ent-3",
            match_result=MatchResult.POTENTIAL_MATCH,
            matched_entry_id=None,
            confidence=0.5,
            screened_at=datetime(2026, 8, 8, 8, 8, 8, tzinfo=timezone.utc),
        )
        assert json.loads(json.dumps(result.to_dict())) == result.to_dict()
        assert result.to_dict()["match_result"] == "POTENTIAL_MATCH"


class TestEventType:
    def test_all_values(self):
        assert EventType.ALERT.value == "ALERT"
        assert EventType.EVIDENCE.value == "EVIDENCE"
        assert EventType.ACTION.value == "ACTION"
        assert EventType.STATUS_CHANGE.value == "STATUS_CHANGE"
        assert EventType.NOTE.value == "NOTE"
        assert EventType.COMMUNICATION.value == "COMMUNICATION"


class TestTimelineEvent:
    def test_to_dict(self):
        event = TimelineEvent(
            event_id="te-1",
            investigation_id="inv-1",
            event_type=EventType.EVIDENCE,
            timestamp=datetime(2026, 9, 9, 9, 9, 9, tzinfo=timezone.utc),
            title="Attached log",
            description="Packet capture attached",
            source="investigator",
            metadata={"hash": "abc123"},
        )
        d = event.to_dict()
        assert d["event_id"] == "te-1"
        assert d["investigation_id"] == "inv-1"
        assert d["event_type"] == "EVIDENCE"
        assert d["timestamp"] == "2026-09-09T09:09:09+00:00"
        assert d["title"] == "Attached log"
        assert d["description"] == "Packet capture attached"
        assert d["source"] == "investigator"
        assert d["metadata"] == {"hash": "abc123"}

    def test_default_metadata(self):
        event = TimelineEvent(
            event_id="te-2",
            investigation_id="inv-1",
            event_type=EventType.NOTE,
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            title="Note",
            description="",
            source="analyst",
        )
        assert event.metadata == {}
        assert event.to_dict()["metadata"] == {}

    def test_json_round_trip(self):
        event = TimelineEvent(
            event_id="te-3",
            investigation_id="inv-2",
            event_type=EventType.STATUS_CHANGE,
            timestamp=datetime(2026, 2, 3, 4, 5, 6, tzinfo=timezone.utc),
            title="Status",
            description="Changed to OPEN",
            source="system",
            metadata={"from": "NEW", "to": "OPEN"},
        )
        assert json.loads(json.dumps(event.to_dict())) == event.to_dict()
        assert event.to_dict()["event_type"] == "STATUS_CHANGE"


class TestTimeline:
    def test_to_dict(self):
        timeline = Timeline(
            timeline_id="tl-1",
            investigation_id="inv-1",
            name="Main timeline",
            events=["te-1", "te-2"],
            created_at=datetime(2026, 3, 4, 5, 6, 7, tzinfo=timezone.utc),
        )
        d = timeline.to_dict()
        assert d["timeline_id"] == "tl-1"
        assert d["investigation_id"] == "inv-1"
        assert d["name"] == "Main timeline"
        assert d["events"] == ["te-1", "te-2"]
        assert d["created_at"] == "2026-03-04T05:06:07+00:00"

    def test_default_events_and_created_at(self):
        timeline = Timeline(
            timeline_id="tl-2", investigation_id="inv-2", name="Empty timeline"
        )
        assert timeline.events == []
        assert isinstance(timeline.created_at, datetime)
        assert timeline.to_dict()["events"] == []

    def test_json_round_trip(self):
        timeline = Timeline(
            timeline_id="tl-3",
            investigation_id="inv-3",
            name="Round trip",
            events=["te-9"],
            created_at=datetime(2026, 4, 5, 6, 7, 8, tzinfo=timezone.utc),
        )
        assert json.loads(json.dumps(timeline.to_dict())) == timeline.to_dict()
        assert timeline.to_dict()["created_at"] == "2026-04-05T06:07:08+00:00"


class TestUnknownEnumConstruction:
    def test_execution_status(self):
        with pytest.raises(ValueError):
            ExecutionStatus("UNKNOWN")

    def test_task_status(self):
        with pytest.raises(ValueError):
            TaskStatus("UNKNOWN")

    def test_metric_type(self):
        with pytest.raises(ValueError):
            MetricType("BOGUS")

    def test_threat_level(self):
        with pytest.raises(ValueError):
            ThreatLevel("BOGUS")

    def test_watchlist_type(self):
        with pytest.raises(ValueError):
            WatchlistType("BOGUS")

    def test_match_result(self):
        with pytest.raises(ValueError):
            MatchResult("BOGUS")

    def test_event_type(self):
        with pytest.raises(ValueError):
            EventType("BOGUS")

    def test_by_value_round_trip(self):
        assert ExecutionStatus("RUNNING") is ExecutionStatus.RUNNING
        assert TaskStatus("SKIPPED") is TaskStatus.SKIPPED
        assert MetricType("FRAUD") is MetricType.FRAUD
        assert ThreatLevel("RED") is ThreatLevel.RED
        assert WatchlistType("PEP") is WatchlistType.PEP
        assert MatchResult("NO_MATCH") is MatchResult.NO_MATCH
        assert EventType("ACTION") is EventType.ACTION
