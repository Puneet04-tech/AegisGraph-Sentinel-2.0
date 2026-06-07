"""Lightweight runtime service failure recovery coordinator."""

from __future__ import annotations

import inspect
from typing import Any, Callable, Dict, Optional

from ..audit import log_audit_event
from ..observability import get_logger
from .events.event_types import RecoveryTriggeredEvent
from .health_monitor import RuntimeHealthMonitor

_logger = get_logger("runtime.recovery")


class RecoveryManager:
    """Manages service recovery actions and prevents infinite restart loops."""

    def get_registered_names(self) -> list[str]:
        """Return a list of service names that have registered recovery callbacks.
        This provides a public way to discover registered services without exposing the private _callbacks dict.
        """
        return list(self._callbacks.keys())

    def __init__(
        self,
        health_monitor: RuntimeHealthMonitor,
        logger: Optional[Any] = None,
        dispatcher: Optional[Any] = None,
        resource_manager: Optional[Any] = None,
    ) -> None:
        self.health_monitor = health_monitor
        self._callbacks: Dict[str, Callable[[], Any]] = {}
        self._max_attempts: Dict[str, int] = {}
        self._logger = logger or _logger
        self._dispatcher = dispatcher  # Optional[EventDispatcher]
        self._resource_manager = resource_manager

    def _audit(self, event_type: str, severity: str = "info", **metadata: Any) -> None:
        try:
            log_audit_event(
                event_type=event_type,
                severity=severity,
                source="recovery_manager",
                metadata=metadata,
            )
        except Exception:
            self._logger.debug("Recovery audit recording failed", exc_info=True)

    def set_resource_manager(self, resource_manager: Any) -> None:
        """Attach optional recovery throttling without changing construction API."""
        self._resource_manager = resource_manager

    def register_recovery_callback(self, name: str, callback: Callable[[], Any], max_attempts: int = 3) -> None:
        """Register a recovery/restart callback for a service."""
        self._callbacks[name] = callback
        self._max_attempts[name] = max_attempts
        self._logger.info(
            f"Registered recovery callback for: {name} (max_attempts: {max_attempts})",
            event_type="recovery_callback_registered",
            metadata={"service": name, "max_attempts": max_attempts},
        )

    async def handle_failure(self, name: str) -> bool:
        """
        Coordinates the recovery attempt for a service.
        Returns True if recovery was successfully attempted, False otherwise.
        """
        callback = self._callbacks.get(name)
        if callback is None:
            self._logger.info(
                f"No recovery callback registered for service: {name}",
                event_type="recovery_no_callback",
                metadata={"service": name},
            )
            return False

        snapshot = self.health_monitor.get_health_snapshot()
        health = snapshot.get(name)
        if health is None:
            self._logger.warning(
                f"Attempted recovery for unregistered service: {name}",
                event_type="recovery_unregistered_service",
                metadata={"service": name},
            )
            return False

        max_attempts = self._max_attempts.get(name, 3)
        if health.restart_attempts >= max_attempts:
            self._logger.error(
                f"Service {name} reached maximum recovery attempts ({max_attempts}). Stopping recovery.",
                event_type="recovery_max_attempts_exceeded",
                metadata={
                    "service": name,
                    "restart_attempts": health.restart_attempts,
                    "max_attempts": max_attempts,
                },
            )
            self._audit(
                "recovery_max_attempts_exceeded",
                "error",
                service=name,
                restart_attempts=health.restart_attempts,
                max_attempts=max_attempts,
            )
            return False

        if self._resource_manager is not None and not self._resource_manager.can_start_recovery():
            self._logger.warning(
                f"Recovery throttled for service: {name}",
                event_type="recovery_throttled",
                metadata={"service": name},
            )
            self._audit("recovery_throttled", "warning", service=name)
            return False

        self.health_monitor.increment_restart_attempts(name)
        new_attempt_count = health.restart_attempts + 1

        self._logger.info(
            f"Attempting recovery for service: {name} (attempt {new_attempt_count}/{max_attempts})",
            event_type="recovery_attempt_started",
            metadata={
                "service": name,
                "attempt": new_attempt_count,
                "max_attempts": max_attempts,
            },
        )
        self._audit(
            "recovery_attempt_started",
            service=name,
            attempt=new_attempt_count,
            max_attempts=max_attempts,
        )

        # Emit RecoveryTriggeredEvent before spawning the callback task.
        if self._dispatcher is not None:
            self._dispatcher.dispatch(
                RecoveryTriggeredEvent(
                    source="recovery_manager",
                    payload={
                        "service": name,
                        "attempt": new_attempt_count,
                        "max_attempts": max_attempts,
                    },
                )
            )

        import asyncio

        async def run_callback_safely():
            try:
                res = callback()
                if inspect.isawaitable(res):
                    await res
                self._logger.info(
                    f"Recovery callback executed successfully for service: {name}",
                    event_type="recovery_attempt_success",
                    metadata={"service": name},
                )
                self._audit("recovery_attempt_success", service=name)
            except Exception as exc:
                self._logger.error(
                    f"Recovery callback failed for service: {name}: {exc}",
                    event_type="recovery_attempt_failed",
                    metadata={"service": name, "error": str(exc)},
                )
                self._audit("recovery_attempt_failed", "error", service=name, error=str(exc))
                self.health_monitor.mark_failed(name, error=f"Recovery failed: {exc}")

        await run_callback_safely()
        return True
