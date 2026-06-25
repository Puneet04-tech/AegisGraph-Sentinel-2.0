"""
Sentinel Log Archival Service

Core business logic for the data lifecycle management cycle:

  1. Identify hot-collection logs older than `threshold_days`.
  2. Promote them to the cold archive collection as ArchiveRecord documents.
  3. Mark the originals as archived (so live queries skip them instantly).
  4. Purge marked documents from the hot collection to reclaim memory / disk.
  5. Record an ArchivalRunSummary for audit and observability.

Design notes
------------
- The service is intentionally stateless; all state lives in SentinelLogStore.
- Batch size is configurable to avoid long lock hold times on large datasets.
- Every step is logged via the project's structured logger so failures surface
  in existing dashboards without any extra wiring.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from .models import ArchivalRunSummary, ArchivalStatus, ArchiveRecord
from .store import SentinelLogStore, get_sentinel_log_store

logger = logging.getLogger(__name__)

# Default archival threshold: migrate logs older than 30 days
DEFAULT_THRESHOLD_DAYS: int = 30

# Number of log documents to process per batch to limit lock hold time
DEFAULT_BATCH_SIZE: int = 500


class ArchivalService:
    """
    Orchestrates one complete archival cycle.

    Parameters
    ----------
    store:
        The SentinelLogStore to operate on.  Defaults to the module-level
        singleton so callers do not need to wire dependencies manually.
    threshold_days:
        Logs created more than this many days ago are candidates for archival.
    batch_size:
        Maximum number of documents moved per internal batch within a single
        run.  Helps bound memory usage on very large datasets.
    """

    def __init__(
        self,
        store: Optional[SentinelLogStore] = None,
        threshold_days: int = DEFAULT_THRESHOLD_DAYS,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ) -> None:
        self._store = store or get_sentinel_log_store()
        self._threshold_days = threshold_days
        self._batch_size = batch_size

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> ArchivalRunSummary:
        """
        Execute a single archival cycle and return the run summary.

        Safe to call concurrently — the underlying store uses an RLock so
        two simultaneous runs will serialize safely, though overlapping runs
        are not expected under normal scheduler operation.
        """
        summary = ArchivalRunSummary(
            threshold_days=self._threshold_days,
            status=ArchivalStatus.RUNNING,
        )
        summary.status = ArchivalStatus.RUNNING

        logger.info(
            "Archival run started",
            extra={
                "run_id": summary.run_id,
                "threshold_days": self._threshold_days,
            },
        )

        try:
            archived, failed, scanned = self._execute(summary.run_id)
            summary.finish(archived=archived, failed=failed, scanned=scanned)

        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "Archival run failed with an unhandled exception",
                extra={"run_id": summary.run_id},
            )
            summary.finish(archived=0, failed=0, scanned=0, error=str(exc))

        finally:
            self._store.save_run_summary(summary)

        logger.info(
            "Archival run finished",
            extra={
                "run_id": summary.run_id,
                "status": summary.status.value,
                "scanned": summary.documents_scanned,
                "archived": summary.documents_archived,
                "failed": summary.documents_failed,
            },
        )
        return summary

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _execute(self, run_id: str) -> tuple[int, int, int]:
        """
        Core migration logic.

        Returns (archived_count, failed_count, scanned_count).
        """
        threshold = datetime.now(timezone.utc) - timedelta(days=self._threshold_days)

        # Step 1 — identify candidates from the hot collection
        candidates = self._store.get_logs_older_than(threshold)
        scanned = len(candidates)

        if not candidates:
            logger.info(
                "No logs eligible for archival",
                extra={"threshold_days": self._threshold_days},
            )
            return 0, 0, 0

        logger.info(
            "Found eligible logs for archival",
            extra={"count": scanned, "threshold": threshold.isoformat()},
        )

        archived = 0
        failed = 0

        # Step 2 — process in batches to keep lock hold times bounded
        for batch_start in range(0, scanned, self._batch_size):
            batch = candidates[batch_start : batch_start + self._batch_size]

            try:
                archive_records: List[ArchiveRecord] = [
                    ArchiveRecord.from_sentinel_log(log, run_id) for log in batch
                ]

                # Step 3 — write to cold collection
                self._store.add_archive_records(archive_records)

                # Step 4 — mark originals as archived in hot collection
                batch_ids = [log.log_id for log in batch]
                updated = self._store.mark_archived(batch_ids)

                archived += updated
                logger.debug(
                    "Batch archived",
                    extra={
                        "run_id": run_id,
                        "batch_size": len(batch),
                        "updated": updated,
                    },
                )

            except Exception as exc:  # noqa: BLE001
                failed += len(batch)
                logger.error(
                    "Batch archival failed",
                    extra={
                        "run_id": run_id,
                        "batch_start": batch_start,
                        "error": str(exc),
                    },
                )

        # Step 5 — purge archived docs from hot collection to free resources
        if archived > 0:
            purged = self._store.purge_archived_from_hot()
            logger.info(
                "Purged archived documents from hot collection",
                extra={"purged": purged},
            )

        return archived, failed, scanned
