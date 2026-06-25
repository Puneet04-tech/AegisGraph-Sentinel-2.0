"""
Archival Scheduler

Wraps the ArchivalService in a background thread that fires once every 24 hours
(configurable).  Uses Python's built-in `threading` + `time.sleep` so there is
no extra dependency to install, mirroring the approach already used by
`database/automated_backup.py` in this project.

For production deployments that prefer APScheduler or Celery Beat, the
`ArchivalService.run()` method can be called directly from any scheduler
without modification.

Environment variables
---------------------
ARCHIVAL_THRESHOLD_DAYS   int  default 30   — age in days before a log is archived
ARCHIVAL_BATCH_SIZE       int  default 500  — documents per internal batch
ARCHIVAL_INTERVAL_HOURS   int  default 24   — how often the scheduler fires
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Optional

from .archival_service import ArchivalService, DEFAULT_THRESHOLD_DAYS, DEFAULT_BATCH_SIZE
from .store import SentinelLogStore, get_sentinel_log_store

logger = logging.getLogger(__name__)


class ArchivalScheduler:
    """
    Background daemon that runs the archival cycle on a fixed interval.

    Usage
    -----
    ::

        scheduler = ArchivalScheduler()
        scheduler.start()   # non-blocking; returns immediately

        # later, on shutdown:
        scheduler.stop()
    """

    def __init__(
        self,
        store: Optional[SentinelLogStore] = None,
        threshold_days: Optional[int] = None,
        batch_size: Optional[int] = None,
        interval_hours: Optional[float] = None,
    ) -> None:
        self._store = store or get_sentinel_log_store()

        self._threshold_days: int = int(
            threshold_days
            if threshold_days is not None
            else os.getenv("ARCHIVAL_THRESHOLD_DAYS", DEFAULT_THRESHOLD_DAYS)
        )
        self._batch_size: int = int(
            batch_size
            if batch_size is not None
            else os.getenv("ARCHIVAL_BATCH_SIZE", DEFAULT_BATCH_SIZE)
        )
        self._interval_seconds: float = float(
            interval_hours * 3600
            if interval_hours is not None
            else int(os.getenv("ARCHIVAL_INTERVAL_HOURS", 24)) * 3600
        )

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background archival worker thread (non-blocking)."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("ArchivalScheduler is already running; ignoring start()")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._worker,
            name="archival-scheduler",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "ArchivalScheduler started",
            extra={
                "threshold_days": self._threshold_days,
                "interval_hours": self._interval_seconds / 3600,
            },
        )

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the background thread to stop and wait for it to exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning("ArchivalScheduler thread did not exit within timeout")
            else:
                logger.info("ArchivalScheduler stopped cleanly")
        self._thread = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------

    def _worker(self) -> None:
        """
        Main loop: run archival immediately on start, then sleep until next
        interval or until stop() is called.
        """
        logger.info("Archival background worker started")

        while not self._stop_event.is_set():
            self._run_once()

            # Sleep in small increments so stop() can interrupt quickly.
            _sleep_interruptible(self._interval_seconds, self._stop_event)

        logger.info("Archival background worker exiting")

    def _run_once(self) -> None:
        """Execute one archival cycle and swallow any unhandled exception."""
        try:
            service = ArchivalService(
                store=self._store,
                threshold_days=self._threshold_days,
                batch_size=self._batch_size,
            )
            summary = service.run()
            logger.info(
                "Scheduled archival run complete",
                extra={"summary": summary.to_dict()},
            )
        except Exception as exc:  # noqa: BLE001
            # Catching broadly here so a single run failure never kills the
            # daemon thread and breaks subsequent scheduled runs.
            logger.exception(
                "Unhandled exception in scheduled archival run",
                extra={"error": str(exc)},
            )


# ---------------------------------------------------------------------------
# Module-level singleton helpers
# ---------------------------------------------------------------------------

_scheduler: Optional[ArchivalScheduler] = None
_scheduler_lock = threading.Lock()


def get_archival_scheduler() -> ArchivalScheduler:
    """Return the module-level ArchivalScheduler singleton."""
    global _scheduler
    if _scheduler is None:
        with _scheduler_lock:
            if _scheduler is None:
                _scheduler = ArchivalScheduler()
    return _scheduler


def start_archival_daemon() -> ArchivalScheduler:
    """
    Convenience function: create (or reuse) the singleton scheduler and start it.

    Mirrors the ``start_backup_daemon()`` interface in
    ``database/automated_backup.py`` for consistency.
    """
    scheduler = get_archival_scheduler()
    if not scheduler.is_running:
        scheduler.start()
    return scheduler


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sleep_interruptible(seconds: float, stop_event: threading.Event, tick: float = 1.0) -> None:
    """Sleep for *seconds* but wake immediately when *stop_event* is set."""
    elapsed = 0.0
    while elapsed < seconds and not stop_event.is_set():
        sleep_time = min(tick, seconds - elapsed)
        time.sleep(sleep_time)
        elapsed += sleep_time
