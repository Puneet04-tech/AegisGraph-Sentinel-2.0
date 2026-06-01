"""Centralized runtime health monitoring container."""

from __future__ import annotations

import time
from threading import Lock
from typing import Any, Dict, Optional

from ..observability import get_logger
from .events.event_types import ServiceFailedEvent, ServiceHealthyEvent
from .service_health import ServiceHealth

_logger = get_logger("runtime.health_monitor")


class RuntimeHealthMonitor:
    """In-memory thread-safe health monitor for services and background tasks."""

    def __init__(
        self,
        unhealthy_threshold: int = 3,
        logger: Optional[Any] = None,
        dispatcher: Optional[Any] = None,
    ) -> None:
        self._services: Dict[str, ServiceHealth] = {}
        self._lock = Lock()
        self._unhealthy_threshold = unhealthy_threshold
        self._logger = logger or _logger
        self._dispatcher = dispatcher  # Optional[EventDispatcher]

    def register_service(self, name: str) -> None:
        """Register a service or background task for tracking."""
        with self._lock:
            if name in self._services:
                return

            self._services[name] = ServiceHealth(
                name=name,
                status="healthy",
                last_heartbeat=time.time(),
            )

            self._logger.info(
                f"Service registered with health monitor: {name}",
                event_type="health_service_registered",
                metadata={"service": name},
            )

    def mark_healthy(self, name: str) -> None:
        """Mark a registered service as healthy, resetting its failures."""
        with self._lock:
            service = self._services.get(name)

            if service is None:
                # Proactively register if not already done
                service = ServiceHealth(
                    name=name,
                    status="healthy",
                    last_heartbeat=time.time(),
                )
                self._services[name] = service

            service.status = "healthy"
            service.failures = 0
            service.last_error = None
            service.last_heartbeat = time.time()

            self._logger.info(
                f"Service marked healthy: {name}",
                event_type="health_service_healthy",
                metadata={"service": name},
            )

        if self._dispatcher is not None:
            self._dispatcher.dispatch(
                ServiceHealthyEvent(
                    source="health_monitor",
                    payload={"service": name},
                )
            )

    def mark_failed(self, name: str, error: Optional[str] = None) -> None:
        """Mark a service as failed, incrementing failures and determining status."""
        with self._lock:
            service = self._services.get(name)

            if service is None:
                service = ServiceHealth(
                    name=name,
                    status="degraded",
                    last_heartbeat=time.time(),
                )
                self._services[name] = service

            service.failures += 1
            service.last_error = error
            service.last_heartbeat = time.time()

            if service.failures >= self._unhealthy_threshold:
                service.status = "unhealthy"
            else:
                service.status = "degraded"

            current_status = service.status
            current_failures = service.failures

            self._logger.warning(
                f"Service marked failed: {name} "
                f"(status: {current_status}, failures: {current_failures})",
                event_type="health_service_failed",
                metadata={
                    "service": name,
                    "status": current_status,
                    "failures": current_failures,
                    "error": error,
                },
            )

        if self._dispatcher is not None:
            self._dispatcher.dispatch(
                ServiceFailedEvent(
                    source="health_monitor",
                    payload={
                        "service": name,
                        "status": current_status,
                        "failures": current_failures,
                        "error": error,
                    },
                )
            )

    def increment_restart_attempts(self, name: str) -> None:
        """Increment restart attempts for a service during recovery."""
        with self._lock:
            service = self._services.get(name)

            if service is not None:
                service.restart_attempts += 1

    def get_health_snapshot(self) -> Dict[str, ServiceHealth]:
        """Return a copy of the current service health states."""
        with self._lock:
            return {
                name: ServiceHealth(
                    name=sh.name,
                    status=sh.status,
                    last_heartbeat=sh.last_heartbeat,
                    failures=sh.failures,
                    restart_attempts=sh.restart_attempts,
                    last_error=sh.last_error,
                )
                for name, sh in self._services.items()
            }

    def get_overall_status(self) -> str:
        """Return the aggregated status of all services."""
        with self._lock:
            if not self._services:
                return "healthy"

            statuses = {sh.status for sh in self._services.values()}

            if "unhealthy" in statuses:
                return "unhealthy"

            if "degraded" in statuses:
                return "degraded"

            return "healthy"