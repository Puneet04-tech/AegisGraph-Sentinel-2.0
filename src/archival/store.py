"""
In-memory store for Sentinel logs (hot) and archive records (cold).

In production this would be backed by MongoDB collections:
  - sentinel_logs          → hot collection, queried by the real-time graph
  - sentinel_logs_archive  → cold collection, queried only for historical ranges

The interface is intentionally kept thin so it can be swapped for a real
MongoDB client (pymongo / motor) without touching the service layer.
"""

from __future__ import annotations

import threading
import uuid
from collections import deque
from datetime import datetime, timezone, timedelta
from typing import Deque, Dict, List, Optional, Tuple

from .models import ArchivalRunSummary, ArchiveRecord, SentinelLog


class SentinelLogStore:
    """
    Thread-safe dual-collection store.

    hot_collection     → recent logs (fast, kept small)
    archive_collection → historical logs (large, queried on demand)
    run_history        → audit trail of every archival cycle
    """

    def __init__(
        self,
        hot_max_size: int = 50_000,
        archive_max_size: int = 500_000,
        run_history_max: int = 365,
    ) -> None:
        self._hot: Deque[SentinelLog] = deque(maxlen=hot_max_size)
        self._archive: Deque[ArchiveRecord] = deque(maxlen=archive_max_size)
        self._run_history: Deque[ArchivalRunSummary] = deque(maxlen=run_history_max)
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Hot collection – primary write path
    # ------------------------------------------------------------------

    def add_log(
        self,
        event_type: str,
        risk_score: float,
        decision: str,
        *,
        source_account: Optional[str] = None,
        target_account: Optional[str] = None,
        metadata: Optional[Dict] = None,
        created_at: Optional[datetime] = None,
    ) -> SentinelLog:
        """Insert a new log into the hot collection and return it."""
        log = SentinelLog(
            log_id=str(uuid.uuid4()),
            event_type=event_type,
            source_account=source_account,
            target_account=target_account,
            risk_score=risk_score,
            decision=decision,
            metadata=metadata or {},
            created_at=created_at or datetime.now(timezone.utc),
        )
        with self._lock:
            self._hot.append(log)
        return log

    def get_hot_logs(
        self,
        *,
        limit: int = 100,
        decision: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[SentinelLog]:
        """Return recent hot logs, newest first, with optional filters."""
        with self._lock:
            results = list(self._hot)

        results.sort(key=lambda l: l.created_at, reverse=True)

        if decision:
            results = [l for l in results if l.decision == decision.upper()]
        if event_type:
            results = [l for l in results if l.event_type == event_type]

        return results[:limit]

    def get_logs_older_than(self, threshold: datetime) -> List[SentinelLog]:
        """Return all hot logs whose created_at is before *threshold*."""
        with self._lock:
            return [l for l in self._hot if l.created_at < threshold and not l.archived]

    def mark_archived(self, log_ids: List[str]) -> int:
        """
        Mark logs as archived in the hot collection.

        In a real MongoDB setup this would be a bulk `$set archived=true`
        update.  Returns the count of logs actually updated.
        """
        id_set = set(log_ids)
        now = datetime.now(timezone.utc)
        count = 0
        with self._lock:
            for log in self._hot:
                if log.log_id in id_set and not log.archived:
                    log.archived = True
                    log.archived_at = now
                    count += 1
        return count

    def purge_archived_from_hot(self) -> int:
        """
        Remove archived logs from the hot collection.

        Call this after a successful archive run to keep the hot collection
        lean.  Returns the number of documents removed.
        """
        with self._lock:
            before = len(self._hot)
            retained = deque(
                (l for l in self._hot if not l.archived),
                maxlen=self._hot.maxlen,
            )
            self._hot = retained
            after = len(self._hot)
        return before - after

    # ------------------------------------------------------------------
    # Archive / cold collection
    # ------------------------------------------------------------------

    def add_archive_records(self, records: List[ArchiveRecord]) -> None:
        """Bulk-insert records into the cold collection."""
        with self._lock:
            self._archive.extend(records)

    def get_archive_logs(
        self,
        *,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        decision: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[ArchiveRecord], int]:
        """
        Query the cold collection.

        Returns a (page, total_count) tuple so the API can paginate results.
        Only called when the user explicitly filters for historical date ranges.
        """
        with self._lock:
            results = list(self._archive)

        # Date range filter
        if start_date:
            results = [r for r in results if r.created_at >= start_date]
        if end_date:
            results = [r for r in results if r.created_at <= end_date]

        # Optional additional filters
        if decision:
            results = [r for r in results if r.decision == decision.upper()]
        if event_type:
            results = [r for r in results if r.event_type == event_type]

        results.sort(key=lambda r: r.created_at, reverse=True)
        total = len(results)
        return results[offset : offset + limit], total

    def get_archive_stats(self) -> Dict:
        """Summary statistics for the cold collection."""
        with self._lock:
            records = list(self._archive)

        if not records:
            return {
                "total_archived": 0,
                "oldest_record": None,
                "newest_record": None,
                "decision_breakdown": {},
            }

        oldest = min(records, key=lambda r: r.created_at)
        newest = max(records, key=lambda r: r.created_at)

        breakdown: Dict[str, int] = {}
        for r in records:
            breakdown[r.decision] = breakdown.get(r.decision, 0) + 1

        return {
            "total_archived": len(records),
            "oldest_record": oldest.created_at.isoformat(),
            "newest_record": newest.created_at.isoformat(),
            "decision_breakdown": breakdown,
        }

    # ------------------------------------------------------------------
    # Run history
    # ------------------------------------------------------------------

    def save_run_summary(self, summary: ArchivalRunSummary) -> None:
        """Persist an archival run summary."""
        with self._lock:
            self._run_history.append(summary)

    def get_run_history(self, limit: int = 30) -> List[ArchivalRunSummary]:
        """Return the most recent archival run summaries, newest first."""
        with self._lock:
            history = list(self._run_history)
        history.sort(key=lambda s: s.started_at, reverse=True)
        return history[:limit]

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def hot_count(self) -> int:
        with self._lock:
            return len(self._hot)

    def archive_count(self) -> int:
        with self._lock:
            return len(self._archive)


# Module-level singleton — shared across the archival service and API routes.
_store: Optional[SentinelLogStore] = None
_store_lock = threading.Lock()


def get_sentinel_log_store() -> SentinelLogStore:
    """Return the module-level SentinelLogStore singleton."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = SentinelLogStore()
    return _store
