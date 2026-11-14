"""Shared background task loops."""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Optional

from ..observability import get_logger


async def honeypot_auto_release_loop(
    get_honeypot_manager: Callable[[], Optional[Any]],
    *,
    interval_seconds: int = 60,
    logger: Any = None,
    health_monitor: Optional[Any] = None,
) -> None:
    """Periodically check honeypot auto-release state until cancelled."""
    task_logger = logger or get_logger("runtime.background_tasks")
    if health_monitor is not None:
        # Liveness for this loop comes from the watchdog's dead-task detection
        # against the TaskRegistry. It must not be heartbeat-graded: the loop
        # wakes every interval_seconds (60s default), which can never satisfy
        # the watchdog's shorter heartbeat timeout, so every idle period looked
        # like a stale heartbeat and degraded /health.
        health_monitor.register_service(
            "honeypot_auto_release", heartbeat_required=False
        )

    try:
        while True:
            await asyncio.sleep(interval_seconds)
            manager = get_honeypot_manager()
            if manager is None:
                # The manager is created lazily on first use, so an idle system
                # legitimately has none yet. That is not a failure.
                task_logger.info(
                    "Honeypot manager not initialised; skipping auto-release check",
                    event_type="honeypot_auto_release_idle",
                )
                continue

            if health_monitor is not None:
                await asyncio.to_thread(health_monitor.mark_healthy, "honeypot_auto_release")
            try:
                await asyncio.to_thread(manager.check_auto_release)
            except Exception as exc:
                task_logger.warning(
                    f"Honeypot auto-release check failed: {exc}",
                    event_type="honeypot_auto_release_error",
                )
                if health_monitor is not None:
                    await asyncio.to_thread(health_monitor.mark_failed, "honeypot_auto_release", error=str(exc))
    except asyncio.CancelledError:
        task_logger.info(
            "Honeypot auto-release loop stopped",
            event_type="honeypot_auto_release_stopped",
        )
        raise
    except Exception as exc:
        if health_monitor is not None:
            await asyncio.to_thread(health_monitor.mark_failed, "honeypot_auto_release", error=str(exc))
        raise
