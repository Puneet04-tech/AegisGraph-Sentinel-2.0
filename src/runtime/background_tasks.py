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
        health_monitor.register_service("honeypot_auto_release")

    try:
        while True:
            await asyncio.sleep(interval_seconds)
            manager = get_honeypot_manager()
            if manager is None:
                if health_monitor is not None:
                    health_monitor.mark_failed("honeypot_auto_release", error="Manager not available")
                continue

            if health_monitor is not None:
                health_monitor.mark_healthy("honeypot_auto_release")
            try:
                await asyncio.to_thread(manager.check_auto_release)
            except Exception as exc:
                task_logger.warning(
                    f"Honeypot auto-release check failed: {exc}",
                    event_type="honeypot_auto_release_error",
                )
                if health_monitor is not None:
                    health_monitor.mark_failed("honeypot_auto_release", error=str(exc))
    except asyncio.CancelledError:
        task_logger.info(
            "Honeypot auto-release loop stopped",
            event_type="honeypot_auto_release_stopped",
        )
        raise
    except Exception as exc:
        if health_monitor is not None:
            health_monitor.mark_failed("honeypot_auto_release", error=str(exc))
        raise
