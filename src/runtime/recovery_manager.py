"""Lightweight runtime service failure recovery coordinator."""

from __future__ import annotations

import inspect
import threading
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
        with self._lock:
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
        self._lock = threading.Lock()
        self._logger = logger or _logger
        self._dispatcher = dispatcher  # Optional[EventDispatcher]
        self._resource_manager = resource_manager
        self._config_registry: Any = None
        self._policy_engine: Any = None
        self._authorization_engine: Any = None
        self._recovery_in_progress: Dict[str, bool] = {}  # Track recovery state per service

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

    def set_config_registry(self, registry: Any) -> None:
        self._config_registry = registry

    def set_policy_engine(self, policy_engine: Any) -> None:
        self._policy_engine = policy_engine

    def set_authorization_engine(self, authorization_engine: Any) -> None:
        self._authorization_engine = authorization_engine

    def get_configuration_status(self) -> Dict[str, Any]:
        return {
            "configuration_count": len(self._config_registry.list_configs()) if self._config_registry else 0,
        }

    def register_recovery_callback(self, name: str, callback: Callable[[], Any], max_attempts: int = 3) -> None:
        """Register a recovery/restart callback for a service."""
        with self._lock:
            self._callbacks[name] = callback
            self._max_attempts[name] = max_attempts
        self._logger.info(
            f"Registered recovery callback for: {name} (max_attempts: {max_attempts})",
            event_type="recovery_callback_registered",
            metadata={"service": name, "max_attempts": max_attempts},
        )

    async def handle_failure(self, name: str, authorization_context: Optional[Any] = None) -> bool:
        """
        Coordinates the recovery attempt for a service.
        Returns True if recovery was successfully attempted, False otherwise.
        """
        if authorization_context is not None and self._authorization_engine is not None:
            role = self._role_from_context(authorization_context)
            auth_result = self._authorization_engine.authorize(role, "recovery.execute")
            if not auth_result.allowed:
                self._audit(
                    "recovery_authorization_denied",
                    "warning",
                    service=name,
                    role=role,
                    reason=auth_result.reason,
                )
                return False

        # Check if recovery is already in progress for this service
        if self._recovery_in_progress.get(name, False):
            self._logger.info(
                f"Recovery already in progress for service: {name}",
                event_type="recovery_already_in_progress",
                metadata={"service": name},
            )
            return False

        with self._lock:
            callback = self._callbacks.get(name)
            max_attempts = self._max_attempts.get(name, 3)
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
        if self._policy_engine is not None:
            result = self._policy_engine.evaluate(
                "max_recovery_attempts",
                {
                    "service": name,
                    "restart_attempts": health.restart_attempts,
                    "max_attempts": max_attempts,
                },
            )
            if not result.allowed:
                self._logger.warning(
                    f"Recovery denied by policy {result.policy_name} for service: {name}",
                    event_type="recovery_policy_denied",
                    metadata={"service": name, "policy": result.policy_name, "reason": result.reason},
                )
                self._audit(
                    "policy_violation",
                    "warning",
                    service=name,
                    policy=result.policy_name,
                    reason=result.reason,
                )
                return False

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

        # Mark recovery as in progress
        self._recovery_in_progress[name] = True

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
            finally:
                # Clear recovery in progress flag
                self._recovery_in_progress[name] = False

        await run_callback_safely()
        return True

    @staticmethod
    def _role_from_context(authorization_context: Any) -> str:
        if isinstance(authorization_context, str):
            return authorization_context
        if isinstance(authorization_context, dict):
            return str(authorization_context.get("role", ""))
        return str(getattr(authorization_context, "role", ""))
