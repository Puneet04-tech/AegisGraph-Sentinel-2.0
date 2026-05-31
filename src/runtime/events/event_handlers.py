"""Built-in lightweight event handlers for AegisGraph Sentinel 2.0.

Handlers here are intentionally small and focused on observability only.
Business logic and orchestration remain in their respective runtime modules.
"""

from __future__ import annotations

from typing import Any

from ...observability import get_logger
from .event_types import (
    BackgroundTaskStartedEvent,
    BackgroundTaskStoppedEvent,
    RecoveryTriggeredEvent,
    RuntimeEvent,
    RuntimeShutdownEvent,
    RuntimeStartedEvent,
    ServiceFailedEvent,
    ServiceHealthyEvent,
    WatchdogAlertEvent,
)

_logger = get_logger("runtime.events.handlers")


# ---------------------------------------------------------------------------
# Observability / logging handler
# ---------------------------------------------------------------------------

def log_event_handler(event: RuntimeEvent) -> None:
    """
    Generic observability handler — logs every runtime event at INFO level.
    Intended to be subscribed to the base RuntimeEvent type so it receives
    all events regardless of their concrete type.
    """
    event_name = type(event).__name__
    _logger.info(
        f"[event_bus] {event_name} from '{event.source}'",
        event_type=f"event_bus_{event_name.lower()}",
        metadata={
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "source": event.source,
            "payload": event.payload,
        },
    )


# ---------------------------------------------------------------------------
# Health-monitor integration hooks
# ---------------------------------------------------------------------------

def on_service_healthy(event: ServiceHealthyEvent) -> None:
    """Hook point for health-monitor integration on service recovery."""
    service = event.payload.get("service", "<unknown>")
    _logger.info(
        f"Health transition → healthy: {service}",
        event_type="event_health_transition_healthy",
        metadata={"service": service, "event_id": event.event_id},
    )


def on_service_failed(event: ServiceFailedEvent) -> None:
    """Hook point for health-monitor integration on service degradation."""
    service = event.payload.get("service", "<unknown>")
    status = event.payload.get("status", "unknown")
    failures = event.payload.get("failures", 0)
    _logger.warning(
        f"Health transition → {status}: {service} (failures={failures})",
        event_type="event_health_transition_failed",
        metadata={
            "service": service,
            "status": status,
            "failures": failures,
            "event_id": event.event_id,
        },
    )


# ---------------------------------------------------------------------------
# Recovery-manager integration hooks
# ---------------------------------------------------------------------------

def on_recovery_triggered(event: RecoveryTriggeredEvent) -> None:
    """Hook point for recovery observability."""
    service = event.payload.get("service", "<unknown>")
    attempt = event.payload.get("attempt", "?")
    max_attempts = event.payload.get("max_attempts", "?")
    _logger.info(
        f"Recovery triggered: {service} (attempt {attempt}/{max_attempts})",
        event_type="event_recovery_triggered",
        metadata={
            "service": service,
            "attempt": attempt,
            "max_attempts": max_attempts,
            "event_id": event.event_id,
        },
    )


# ---------------------------------------------------------------------------
# Watchdog integration hooks
# ---------------------------------------------------------------------------

def on_watchdog_alert(event: WatchdogAlertEvent) -> None:
    """Hook point for watchdog alert observability."""
    alert_type = event.payload.get("alert_type", "unknown")
    target = event.payload.get("target", "<unknown>")
    _logger.warning(
        f"Watchdog alert [{alert_type}]: {target}",
        event_type="event_watchdog_alert",
        metadata={
            "alert_type": alert_type,
            "target": target,
            "event_id": event.event_id,
        },
    )
