"""Lightweight background watchdog to monitor service heartbeats and task lifecycles."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Optional

from ..observability import get_logger
from .events.event_types import WatchdogAlertEvent
from .health_monitor import RuntimeHealthMonitor
from .recovery_manager import RecoveryManager
from .task_registry import TaskRegistry

_logger = get_logger("runtime.watchdog")


class RuntimeWatchdog:
    """Watchdog process that monitors registered tasks and services and coordinates recovery."""

    def __init__(
        self,
        health_monitor: RuntimeHealthMonitor,
        task_registry: TaskRegistry,
        recovery_manager: Optional[RecoveryManager] = None,
        heartbeat_timeout_seconds: float = 30.0,
        logger: Optional[Any] = None,
        dispatcher: Optional[Any] = None,
    ) -> None:
        self.health_monitor = health_monitor
        self.task_registry = task_registry
        self.recovery_manager = recovery_manager
        self.heartbeat_timeout_seconds = heartbeat_timeout_seconds
        self._logger = logger or _logger
        self._watchdog_task: Optional[asyncio.Task] = None
        self._dispatcher = dispatcher  # Optional[EventDispatcher]

    async def start(self, interval_seconds: float = 10.0) -> None:
        """Start the periodic watchdog loop."""
        if self._watchdog_task is not None and not self._watchdog_task.done():
            self._logger.warning("Watchdog is already running", event_type="watchdog_already_running")
            return

        async def _loop():
            self._logger.info(
                f"Watchdog loop started (interval: {interval_seconds}s, heartbeat_timeout: {self.heartbeat_timeout_seconds}s)",
                event_type="watchdog_started",
                metadata={"interval": interval_seconds, "timeout": self.heartbeat_timeout_seconds},
            )
            try:
                while True:
                    await asyncio.sleep(interval_seconds)
                    await self.validate_health()
            except asyncio.CancelledError:
                self._logger.info("Watchdog loop stopped", event_type="watchdog_cancelled")
                raise
            except Exception as exc:
                self._logger.critical(
                    f"Watchdog loop crashed: {exc}",
                    event_type="watchdog_crashed",
                    metadata={"error": str(exc)},
                )
                raise

        self._watchdog_task = asyncio.create_task(_loop(), name="runtime_watchdog")

    async def stop(self) -> None:
        """Stop the periodic watchdog loop."""
        if self._watchdog_task is not None and not self._watchdog_task.done():
            self._watchdog_task.cancel()
            try:
                await self._watchdog_task
            except asyncio.CancelledError:
                pass
            self._watchdog_task = None

    async def validate_health(self) -> None:
        """Perform periodic health validation for heartbeats and active tasks."""
        current_time = time.time()
        snapshot = self.health_monitor.get_health_snapshot()
        failed_services = set()

        # 1. Stale Heartbeat Detection
        stale_coros = []
        for name, health in snapshot.items():
            if health.status in ("healthy", "degraded"):
                elapsed = current_time - health.last_heartbeat
                if elapsed > self.heartbeat_timeout_seconds:
                    self._logger.warning(
                        f"Watchdog detected stale heartbeat for service: {name} (elapsed: {elapsed:.1f}s)",
                        event_type="watchdog_stale_heartbeat",
                        metadata={"service": name, "elapsed": elapsed},
                    )
                    self.health_monitor.mark_failed(
                        name,
                        error=f"Stale heartbeat: no response in {elapsed:.1f} seconds"
                    )
                    failed_services.add(name)
                    if self._dispatcher is not None:
                        self._dispatcher.dispatch(
                            WatchdogAlertEvent(
                                source="watchdog",
                                payload={
                                    "alert_type": "stale_heartbeat",
                                    "target": name,
                                    "elapsed_seconds": elapsed,
                                },
                            )
                        )
                    if self.recovery_manager:
                        stale_coros.append(self.recovery_manager.handle_failure(name))
        if stale_coros:
            await asyncio.gather(*stale_coros)

        # 2. Dead Task Detection for Registered Runtime Tasks
        active_tasks = self.task_registry.get_active_tasks()
        active_names = {task.name for task in active_tasks}

        # Collect recovery tasks to run concurrently
        recovery_coros = []
        if self.recovery_manager:
            # Use public accessor to get registered service names
            registered_names = self.recovery_manager.get_registered_names()
            for name in registered_names:
                if name in failed_services:
                    continue  # Already handled in stale heartbeat loop
                health = snapshot.get(name)
                if health is not None and health.status != "unhealthy":
                    if name not in active_names:
                        self._logger.warning(
                            f"Watchdog detected dead background task: {name}",
                            event_type="watchdog_dead_task",
                            metadata={"task": name},
                        )
                        self.health_monitor.mark_failed(
                            name,
                            error="Dead task: background task has stopped running"
                        )
                        if self._dispatcher is not None:
                            self._dispatcher.dispatch(
                                WatchdogAlertEvent(
                                    source="watchdog",
                                    payload={
                                        "alert_type": "dead_task",
                                        "target": name,
                                    },
                                )
                            )
                        recovery_coros.append(self.recovery_manager.handle_failure(name))
        # Await all recovery callbacks concurrently
        if recovery_coros:
            await asyncio.gather(*recovery_coros)
