"""Comprehensive tests for the audit trail export helpers."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from src.audit.exporter import filter_records, summarize, to_csv, to_json

SAMPLE = [
    {"action": "login", "user": "alice", "timestamp": "2026-01-01T10:00:00Z"},
    {"action": "logout", "user": "alice", "timestamp": "2026-01-01T10:05:00Z"},
    {"action": "login", "user": "bob", "timestamp": "2026-01-02T09:00:00Z"},
    {"action": "export", "user": "carol", "timestamp": "2026-01-03T12:30:00Z"},
]


def test_to_csv_basic_with_header():
    result = to_csv(SAMPLE)
    rows = list(csv.reader(io.StringIO(result)))
    assert rows[0] == ["action", "user", "timestamp"]
    assert rows[1] == ["login", "alice", "2026-01-01T10:00:00Z"]
    assert rows[-1] == ["export", "carol", "2026-01-03T12:30:00Z"]
    assert len(rows) == len(SAMPLE) + 1


def test_to_csv_field_names_override():
    result = to_csv(SAMPLE, field_names=["user", "action"])
    rows = list(csv.reader(io.StringIO(result)))
    assert rows[0] == ["user", "action"]
    assert rows[1] == ["alice", "login"]
    assert "timestamp" not in rows[1]


def test_to_csv_handles_embedded_specials():
    records = [
        {"action": "note", "user": "a,b", "timestamp": 'say "hi"\nagain'},
        {"action": "note", "user": "b", "timestamp": "plain"},
    ]
    result = to_csv(records)
    rows = list(csv.reader(io.StringIO(result)))
    assert rows[1] == ["note", "a,b", 'say "hi"\nagain']
    assert rows[2] == ["note", "b", "plain"]


def test_to_csv_writes_to_filepath(tmp_path):
    target = tmp_path / "audit.csv"
    returned = to_csv(SAMPLE, filepath=str(target))
    assert returned == str(target)
    assert target.exists()
    rows = list(csv.reader(target.open(encoding="utf-8")))
    assert rows[0] == ["action", "user", "timestamp"]
    assert len(rows) == len(SAMPLE) + 1


def test_to_json_returns_parseable_unicode():
    records = [{"action": "login", "user": "sébastien", "timestamp": "2026-01-01T00:00:00Z"}]
    result = to_json(records)
    parsed = json.loads(result)
    assert parsed == records
    assert "sébastien" in result


def test_to_json_writes_file(tmp_path):
    target = tmp_path / "audit.json"
    returned = to_json(SAMPLE, filepath=str(target))
    assert returned == str(target)
    assert target.exists()
    assert json.loads(target.read_text(encoding="utf-8")) == SAMPLE


def test_filter_records_by_action():
    result = filter_records(SAMPLE, action="login")
    assert [r["user"] for r in result] == ["alice", "bob"]


def test_filter_records_by_user():
    result = filter_records(SAMPLE, user="alice")
    assert len(result) == 2
    assert all(r["user"] == "alice" for r in result)


def test_filter_records_by_timestamp_range():
    result = filter_records(
        SAMPLE, after="2026-01-01T10:00:00Z", before="2026-01-03T00:00:00Z"
    )
    assert [r["user"] for r in result] == ["alice", "bob"]


def test_filter_records_combined_criteria():
    result = filter_records(
        SAMPLE, action="login", user="alice", after="2026-01-01T00:00:00Z"
    )
    assert len(result) == 1
    assert result[0]["timestamp"] == "2026-01-01T10:00:00Z"


def test_filter_records_missing_field_excluded():
    records = [
        {"action": "login", "user": "alice", "timestamp": "2026-01-01T00:00:00Z"},
        {"action": "logout", "timestamp": "2026-01-02T00:00:00Z"},
        {"action": "login"},
    ]
    by_action = filter_records(records, action="login")
    assert len(by_action) == 2
    by_user = filter_records(records, user="alice")
    assert len(by_user) == 1
    by_ts = filter_records(records, after="2026-01-01T00:00:00Z")
    assert len(by_ts) == 1


def test_filter_records_datetime_objects():
    records = [
        {"action": "login", "user": "alice", "timestamp": datetime(2026, 1, 1)},
        {"action": "login", "user": "bob", "timestamp": datetime(2026, 1, 5)},
    ]
    result = filter_records(
        records,
        after=datetime(2026, 1, 2),
        before=datetime(2026, 1, 10),
        action="login",
    )
    assert len(result) == 1
    assert result[0]["user"] == "bob"


def test_summarize_counts_and_extremes():
    summary = summarize(SAMPLE)
    assert summary["total"] == 4
    assert summary["actions"] == {"login": 2, "logout": 1, "export": 1}
    assert summary["users"] == {"alice": 2, "bob": 1, "carol": 1}
    assert summary["first_ts"] == "2026-01-01T10:00:00Z"
    assert summary["last_ts"] == "2026-01-03T12:30:00Z"


def test_summarize_empty_records():
    summary = summarize([])
    assert summary == {
        "total": 0,
        "actions": {},
        "users": {},
        "first_ts": None,
        "last_ts": None,
    }


def test_summarize_parsed_datetime_timestamps():
    records = [
        {"action": "login", "user": "alice", "timestamp": datetime(2026, 1, 5)},
        {"action": "login", "user": "bob", "timestamp": datetime(2026, 1, 1)},
    ]
    summary = summarize(records)
    assert summary["first_ts"] == "2026-01-01T00:00:00"
    assert summary["last_ts"] == "2026-01-05T00:00:00"


def test_to_csv_empty_records_header_only():
    result = to_csv([])
    rows = list(csv.reader(io.StringIO(result)))
    assert rows == [[]]


def test_to_csv_empty_records_header_only_with_fields():
    result = to_csv([], field_names=["action", "user"])
    rows = list(csv.reader(io.StringIO(result)))
    assert rows == [["action", "user"]]
