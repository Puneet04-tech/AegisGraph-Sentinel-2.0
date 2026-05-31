"""Centralized runtime event subscription registration.

Call ``register_default_subscriptions(bus)`` once during startup to wire
all built-in handlers to the event bus.  Subscriptions are grouped by
concern so it is easy to see and control which handlers are active.
"""

from __future__ import annotations

from .event_bus import RuntimeEventBus
from .event_handlers import (
    log_event_handler,
    on_recovery_triggered,
    on_service_failed,
    on_service_healthy,
    on_watchdog_alert,
)
from .event_types import (
    RecoveryTriggeredEvent,
    RuntimeEvent,
    ServiceFailedEvent,
    ServiceHealthyEvent,
    WatchdogAlertEvent,
)


async def register_default_subscriptions(bus: RuntimeEventBus) -> None:
    """
    Wire the default built-in handlers to *bus*.

    Groups:
    - Observability: generic log_event_handler subscribes to the base type
      so every event gets an automatic log entry.
    - Health monitoring: targeted handlers for health state transitions.
    - Recovery: handler for recovery trigger events.
    - Watchdog: handler for watchdog alert events.
    """
    # ── Observability ───────────────────────────────────────────────────
    await bus.subscribe(RuntimeEvent, log_event_handler)

    # ── Health monitoring ────────────────────────────────────────────────
    await bus.subscribe(ServiceHealthyEvent, on_service_healthy)
    await bus.subscribe(ServiceFailedEvent, on_service_failed)

    # ── Recovery ────────────────────────────────────────────────────────
    await bus.subscribe(RecoveryTriggeredEvent, on_recovery_triggered)

    # ── Watchdog ─────────────────────────────────────────────────────────
    await bus.subscribe(WatchdogAlertEvent, on_watchdog_alert)
