"""Runtime event infrastructure for AegisGraph Sentinel 2.0.

Public API
----------
* RuntimeEvent and all concrete event types
* RuntimeEventBus  – async-safe pub/sub event bus
* EventDispatcher  – bounded background dispatch queue
* register_default_subscriptions – wire built-in handlers at startup
"""

from .dispatcher import EventDispatcher
from .event_bus import RuntimeEventBus
from .event_handlers import (
    log_event_handler,
    on_recovery_triggered,
    on_service_failed,
    on_service_healthy,
    on_watchdog_alert,
    on_sentinel_alert,
)
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
    SentinelAlertEvent,
)
from .subscriptions import register_default_subscriptions

__all__ = [
    # Core infrastructure
    "RuntimeEventBus",
    "EventDispatcher",
    "register_default_subscriptions",
    # Event types
    "RuntimeEvent",
    "RuntimeStartedEvent",
    "RuntimeShutdownEvent",
    "ServiceHealthyEvent",
    "ServiceFailedEvent",
    "BackgroundTaskStartedEvent",
    "BackgroundTaskStoppedEvent",
    "RecoveryTriggeredEvent",
    "WatchdogAlertEvent",
    "SentinelAlertEvent",
    # Handlers (exposed for testing and custom subscriptions)
    "log_event_handler",
    "on_service_healthy",
    "on_service_failed",
    "on_recovery_triggered",
    "on_watchdog_alert",
    "on_sentinel_alert",
]
