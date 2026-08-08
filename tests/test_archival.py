"""Unit tests for the Sentinel log archival lifecycle.

Covers ``src.archival.store.SentinelLogStore``, ``ArchivalService``,
``ArchivalRunSummary`` and ``ArchivalScheduler``. All tests are pure unit
tests operating on the in-memory store so they run without MongoDB.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from src.archival.archival_service import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_THRESHOLD_DAYS,
    ArchivalService,
)
from src.archival.models import (
    ArchiveRecord,
    ArchivalRunSummary,
    ArchivalStatus,
    SentinelLog,
)
from src.archival.scheduler import ArchivalScheduler, _sleep_interruptible
from src.archival.store import SentinelLogStore


def _make_log(
    store: SentinelLogStore,
    *,
    event_type: str = "fraud_check",
    risk_score: float = 0.4,
    decision: str = "ALLOW",
    created_at: datetime | None = None,
) -> SentinelLog:
    """Create and insert a log, returning it so tests can inspect IDs."""
    return store.add_log(
        event_type=event_type,
        risk_score=risk_score,
        decision=decision,
        created_at=created_at or datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# SentinelLogStore — hot collection
# ---------------------------------------------------------------------------


class TestSentinelLogStoreHot:
    def test_add_log_persists_all_fields(self):
        store = SentinelLogStore()
        log = _make_log(store, event_type="threat_detected", risk_score=0.9, decision="BLOCK")

        assert store.get_hot_logs() == [log]
        assert log.event_type == "threat_detected"
        assert log.risk_score == 0.9
        assert log.decision == "BLOCK"
        assert log.archived is False
        assert log.archived_at is None

    def test_get_hot_logs_returns_newest_first(self):
        store = SentinelLogStore()
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        older = _make_log(store, created_at=base)
        newer = _make_log(store, created_at=base + timedelta(hours=2))
        oldest = _make_log(store, created_at=base - timedelta(hours=2))

        result = store.get_hot_logs()
        assert [l.log_id for l in result] == [newer.log_id, older.log_id, oldest.log_id]

    def test_get_hot_logs_filters_by_decision(self):
        store = SentinelLogStore()
        blocked = _make_log(store, decision="BLOCK")
        _make_log(store, decision="ALLOW")

        result = store.get_hot_logs(decision="BLOCK")
        assert [l.log_id for l in result] == [blocked.log_id]

    def test_get_hot_logs_filters_by_event_type(self):
        store = SentinelLogStore()
        threat = _make_log(store, event_type="threat_detected")
        _make_log(store, event_type="fraud_check")

        result = store.get_hot_logs(event_type="threat_detected")
        assert [l.log_id for l in result] == [threat.log_id]

    def test_get_hot_logs_respects_limit(self):
        store = SentinelLogStore()
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(5):
            _make_log(store, created_at=base + timedelta(minutes=i))

        result = store.get_hot_logs(limit=3)
        assert len(result) == 3

    def test_get_logs_older_than_returns_only_old_and_unarchived(self):
        store = SentinelLogStore()
        threshold = datetime(2026, 6, 1, tzinfo=timezone.utc)
        old = _make_log(store, created_at=threshold - timedelta(days=10))
        _make_log(store, created_at=threshold + timedelta(days=1))

        result = store.get_logs_older_than(threshold)
        assert [l.log_id for l in result] == [old.log_id]

    def test_get_logs_older_than_excludes_archived(self):
        store = SentinelLogStore()
        threshold = datetime(2026, 6, 1, tzinfo=timezone.utc)
        old = _make_log(store, created_at=threshold - timedelta(days=10))
        store.mark_archived([old.log_id])

        assert store.get_logs_older_than(threshold) == []

    def test_mark_archived_sets_timestamp_and_is_idempotent(self):
        store = SentinelLogStore()
        log = _make_log(store)
        other = _make_log(store)

        assert store.mark_archived([log.log_id]) == 1
        assert log.archived is True
        assert log.archived_at is not None
        assert other.archived is False

        # Second call must not double-count already-archived logs.
        assert store.mark_archived([log.log_id]) == 0

    def test_purge_archived_from_hot_removes_only_archived(self):
        store = SentinelLogStore()
        archived = _make_log(store)
        retained = _make_log(store)
        store.mark_archived([archived.log_id])

        purged = store.purge_archived_from_hot()

        assert purged == 1
        remaining = store.get_hot_logs()
        assert [l.log_id for l in remaining] == [retained.log_id]


# ---------------------------------------------------------------------------
# SentinelLogStore — archive / cold collection
# ---------------------------------------------------------------------------


class TestSentinelLogStoreCold:
    def test_add_and_query_archive_records(self):
        store = SentinelLogStore()
        record = ArchiveRecord(
            log_id="log-1",
            event_type="fraud_check",
            source_account="a",
            target_account="b",
            risk_score=0.8,
            decision="BLOCK",
            metadata={},
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            archived_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            archive_run_id="run-1",
        )
        store.add_archive_records([record])

        page, total = store.get_archive_logs()
        assert total == 1
        assert page[0].log_id == "log-1"

    def test_get_archive_logs_date_range_filter(self):
        store = SentinelLogStore()
        jan = datetime(2026, 1, 15, tzinfo=timezone.utc)
        feb = datetime(2026, 2, 15, tzinfo=timezone.utc)
        mar = datetime(2026, 3, 15, tzinfo=timezone.utc)
        for created in (jan, feb, mar):
            store.add_archive_records(
                [
                    ArchiveRecord(
                        log_id=f"log-{created.month}",
                        event_type="fraud_check",
                        source_account=None,
                        target_account=None,
                        risk_score=0.5,
                        decision="ALLOW",
                        metadata={},
                        created_at=created,
                        archived_at=created,
                        archive_run_id="run-1",
                    )
                ]
            )

        page, total = store.get_archive_logs(
            start_date=datetime(2026, 2, 1, tzinfo=timezone.utc),
            end_date=datetime(2026, 2, 28, tzinfo=timezone.utc),
        )
        assert total == 1
        assert page[0].log_id == "log-2"

    def test_get_archive_logs_decision_and_event_filters(self):
        store = SentinelLogStore()
        for i, (decision, event_type) in enumerate(
            [("BLOCK", "fraud_check"), ("ALLOW", "fraud_check"), ("BLOCK", "suspicious")],
        ):
            store.add_archive_records(
                [
                    ArchiveRecord(
                        log_id=f"log-{i}",
                        event_type=event_type,
                        source_account=None,
                        target_account=None,
                        risk_score=0.5,
                        decision=decision,
                        metadata={},
                        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                        archived_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
                        archive_run_id="run-1",
                    )
                ]
            )

        page, total = store.get_archive_logs(decision="BLOCK", event_type="fraud_check")
        assert total == 1
        assert page[0].log_id == "log-0"

    def test_get_archive_logs_pagination(self):
        store = SentinelLogStore()
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(10):
            store.add_archive_records(
                [
                    ArchiveRecord(
                        log_id=f"log-{i:02d}",
                        event_type="fraud_check",
                        source_account=None,
                        target_account=None,
                        risk_score=0.5,
                        decision="ALLOW",
                        metadata={},
                        created_at=base + timedelta(minutes=i),
                        archived_at=base + timedelta(minutes=i),
                        archive_run_id="run-1",
                    )
                ]
            )

        page, total = store.get_archive_logs(limit=3, offset=2)
        assert total == 10
        assert len(page) == 3
        # Newest first, so offset 2 starts at index 2 of the reversed ordering.
        assert page[0].log_id == "log-07"

    def test_get_archive_stats_empty(self):
        store = SentinelLogStore()
        stats = store.get_archive_stats()
        assert stats["total_archived"] == 0
        assert stats["oldest_record"] is None
        assert stats["decision_breakdown"] == {}

    def test_get_archive_stats_breakdown(self):
        store = SentinelLogStore()
        for i, decision in enumerate(["BLOCK", "BLOCK", "REVIEW"]):
            store.add_archive_records(
                [
                    ArchiveRecord(
                        log_id=f"log-{i}",
                        event_type="fraud_check",
                        source_account=None,
                        target_account=None,
                        risk_score=0.5,
                        decision=decision,
                        metadata={},
                        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                        archived_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
                        archive_run_id="run-1",
                    )
                ]
            )

        stats = store.get_archive_stats()
        assert stats["total_archived"] == 3
        assert stats["decision_breakdown"] == {"BLOCK": 2, "REVIEW": 1}

    def test_add_archive_records_is_idempotent_by_log_id(self):
        store = SentinelLogStore()
        record = ArchiveRecord(
            log_id="log-1",
            event_type="fraud_check",
            source_account=None,
            target_account=None,
            risk_score=0.5,
            decision="ALLOW",
            metadata={},
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            archived_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            archive_run_id="run-1",
        )

        assert store.add_archive_records([record]) == 1

        # Re-writing the same log_id must not create a duplicate.
        assert store.add_archive_records([record]) == 0
        assert store.archive_count() == 1

        # A different log_id is still committed.
        record.log_id = "log-2"
        assert store.add_archive_records([record]) == 1
        assert store.archive_count() == 2

    def test_add_archive_records_dedupes_within_a_single_batch(self):
        store = SentinelLogStore()
        record = ArchiveRecord(
            log_id="log-1",
            event_type="fraud_check",
            source_account=None,
            target_account=None,
            risk_score=0.5,
            decision="ALLOW",
            metadata={},
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            archived_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            archive_run_id="run-1",
        )

        assert store.add_archive_records([record, record]) == 1
        assert store.archive_count() == 1


# ---------------------------------------------------------------------------
# ArchivalService
# ---------------------------------------------------------------------------


class TestArchivalService:
    def test_run_with_no_candidates_produces_completed_summary(self):
        store = SentinelLogStore()
        service = ArchivalService(store=store, threshold_days=DEFAULT_THRESHOLD_DAYS)

        summary = service.run()

        assert summary.status == ArchivalStatus.COMPLETED
        assert summary.documents_scanned == 0
        assert summary.documents_archived == 0
        assert store.get_run_history()[-1].run_id == summary.run_id

    def test_run_archives_only_documents_older_than_threshold(self):
        store = SentinelLogStore()
        now = datetime.now(timezone.utc)
        old = _make_log(store, created_at=now - timedelta(days=60))
        recent = _make_log(store, created_at=now - timedelta(days=1))
        service = ArchivalService(store=store, threshold_days=30)

        summary = service.run()

        assert summary.status == ArchivalStatus.COMPLETED
        assert summary.documents_scanned == 1
        assert summary.documents_archived == 1
        assert old.archived is True
        assert recent.archived is False

        # The archived document moved to cold storage.
        page, total = store.get_archive_logs()
        assert total == 1
        assert page[0].log_id == old.log_id
        assert page[0].archive_run_id == summary.run_id

    def test_run_purges_archived_documents_from_hot(self):
        store = SentinelLogStore()
        now = datetime.now(timezone.utc)
        _make_log(store, created_at=now - timedelta(days=60))
        _make_log(store, created_at=now - timedelta(days=1))

        ArchivalService(store=store, threshold_days=30).run()

        remaining = store.get_hot_logs()
        assert len(remaining) == 1
        assert remaining[0].archived is False

    def test_run_batches_archival_when_candidates_exceed_batch_size(self):
        store = SentinelLogStore()
        now = datetime.now(timezone.utc)
        for i in range(5):
            _make_log(store, created_at=now - timedelta(days=40 + i))
        service = ArchivalService(store=store, threshold_days=30, batch_size=2)

        summary = service.run()

        assert summary.documents_scanned == 5
        assert summary.documents_archived == 5
        assert summary.status == ArchivalStatus.COMPLETED

    def test_run_partial_status_when_a_batch_fails(self, monkeypatch):
        store = SentinelLogStore()
        now = datetime.now(timezone.utc)
        for i in range(4):
            _make_log(store, created_at=now - timedelta(days=40 + i))

        def boom(log_ids):
            raise RuntimeError("simulated storage failure")

        monkeypatch.setattr(store, "mark_archived", boom)
        service = ArchivalService(store=store, threshold_days=30, batch_size=2)

        summary = service.run()

        assert summary.documents_failed == 4
        assert summary.status == ArchivalStatus.PARTIAL

    def test_run_failed_status_on_store_exception(self, monkeypatch):
        store = SentinelLogStore()
        _make_log(store)

        def boom(threshold):
            raise RuntimeError("simulated query failure")

        monkeypatch.setattr(store, "get_logs_older_than", boom)
        service = ArchivalService(store=store, threshold_days=30)

        summary = service.run()

        assert summary.status == ArchivalStatus.FAILED
        assert summary.documents_archived == 0
        assert "simulated query failure" in (summary.error_message or "")

    def test_zero_threshold_archives_everything(self):
        store = SentinelLogStore()
        _make_log(store, created_at=datetime.now(timezone.utc))
        service = ArchivalService(store=store, threshold_days=0)

        summary = service.run()

        assert summary.documents_archived == 1
        assert store.get_hot_logs() == []

    def test_rerun_after_cold_write_failure_does_not_duplicate(self, monkeypatch):
        store = SentinelLogStore()
        now = datetime.now(timezone.utc)
        for i in range(2):
            _make_log(store, created_at=now - timedelta(days=40 + i))
        service = ArchivalService(store=store, threshold_days=30)

        def boom(log_ids):
            raise RuntimeError("simulated storage failure")

        # First run commits records to cold storage but fails to mark the hot
        # logs as archived, so the cycle does not finish.
        monkeypatch.setattr(store, "mark_archived", boom)
        first = service.run()
        assert first.documents_failed == 2
        assert store.archive_count() == 2

        # Re-running must not duplicate the cold records and the hot logs now
        # complete the archival cycle.
        monkeypatch.undo()
        second = service.run()
        assert second.documents_archived == 0
        assert store.archive_count() == 2

        page, total = store.get_archive_logs()
        assert total == 2
        remaining = store.get_hot_logs()
        assert len(remaining) == 2
        assert all(log.archived for log in remaining)


# ---------------------------------------------------------------------------
# ArchivalRunSummary
# ---------------------------------------------------------------------------


class TestArchivalRunSummary:
    def test_finish_sets_completed_status(self):
        summary = ArchivalRunSummary()
        summary.finish(archived=3, failed=0, scanned=5)

        assert summary.status == ArchivalStatus.COMPLETED
        assert summary.documents_archived == 3
        assert summary.completed_at is not None
        assert summary.error_message is None

    def test_finish_sets_partial_status_when_batches_fail(self):
        summary = ArchivalRunSummary()
        summary.finish(archived=2, failed=1, scanned=3)

        assert summary.status == ArchivalStatus.PARTIAL

    def test_finish_sets_failed_status_on_error_without_archives(self):
        summary = ArchivalRunSummary()
        summary.finish(archived=0, failed=0, scanned=0, error="boom")

        assert summary.status == ArchivalStatus.FAILED
        assert summary.error_message == "boom"

    def test_finish_error_with_archives_still_completes(self):
        # A late error that did not prevent archiving and involved no failed
        # documents keeps the COMPLETED status (see ArchivalRunSummary.finish).
        summary = ArchivalRunSummary()
        summary.finish(archived=1, failed=0, scanned=1, error="late failure")

        assert summary.status == ArchivalStatus.COMPLETED
        assert summary.error_message == "late failure"

    def test_to_dict_round_trip(self):
        summary = ArchivalRunSummary(threshold_days=7)
        summary.finish(archived=2, failed=0, scanned=2)

        data = summary.to_dict()
        assert data["status"] == "completed"
        assert data["threshold_days"] == 7
        assert data["documents_archived"] == 2
        assert data["run_id"] == summary.run_id
        assert data["completed_at"] is not None


# ---------------------------------------------------------------------------
# ArchiveRecord
# ---------------------------------------------------------------------------


class TestArchiveRecord:
    def test_from_sentinel_log_preserves_fields(self):
        log = SentinelLog(
            log_id="log-1",
            event_type="fraud_check",
            source_account="src",
            target_account="dst",
            risk_score=0.75,
            decision="REVIEW",
            metadata={"channel": "mobile"},
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        record = ArchiveRecord.from_sentinel_log(log, archive_run_id="run-9")

        assert record.log_id == "log-1"
        assert record.risk_score == 0.75
        assert record.decision == "REVIEW"
        assert record.metadata == {"channel": "mobile"}
        assert record.archive_run_id == "run-9"
        assert record.archived_at is not None

    def test_to_dict_contains_expected_keys(self):
        record = ArchiveRecord(
            log_id="log-1",
            event_type="fraud_check",
            source_account=None,
            target_account=None,
            risk_score=0.5,
            decision="ALLOW",
            metadata={},
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            archived_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            archive_run_id="run-1",
        )
        data = record.to_dict()
        assert data["log_id"] == "log-1"
        assert data["archive_run_id"] == "run-1"
        assert data["archived_at"].startswith("2026-01-02")


# ---------------------------------------------------------------------------
# ArchivalScheduler
# ---------------------------------------------------------------------------


class TestArchivalScheduler:
    def test_start_stop_lifecycle(self):
        store = SentinelLogStore()
        scheduler = ArchivalScheduler(store=store, interval_hours=0.0001)
        assert scheduler.is_running is False

        scheduler.start()
        try:
            assert scheduler.is_running is True
        finally:
            scheduler.stop()

        assert scheduler.is_running is False

    def test_start_is_idempotent_while_running(self):
        scheduler = ArchivalScheduler(
            store=SentinelLogStore(), interval_hours=0.0001
        )
        scheduler.start()
        try:
            first_thread = scheduler._thread
            scheduler.start()
            assert scheduler._thread is first_thread
        finally:
            scheduler.stop()

    def test_scheduler_runs_archival_cycle(self):
        store = SentinelLogStore()
        now = datetime.now(timezone.utc)
        _make_log(store, created_at=now - timedelta(days=60))

        scheduler = ArchivalScheduler(
            store=store, threshold_days=30, interval_hours=0.0001
        )
        scheduler._run_once()

        page, total = store.get_archive_logs()
        assert total == 1

    def test_sleep_interruptible_returns_when_event_set(self):
        stop_event = threading.Event()
        stop_event.set()

        _sleep_interruptible(30.0, stop_event)
        assert stop_event.is_set()

    def test_sleep_interruptible_honours_full_duration(self):
        stop_event = threading.Event()
        _sleep_interruptible(0.01, stop_event)
        assert stop_event.is_set() is False

    def test_interval_seconds_from_hours(self):
        scheduler = ArchivalScheduler(
            store=SentinelLogStore(), interval_hours=1.5
        )
        assert scheduler._interval_seconds == 5400.0
