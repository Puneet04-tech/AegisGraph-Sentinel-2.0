"""Lightweight runtime/domain event models for AegisGraph Sentinel 2.0."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ...security import sanitize_payload


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _new_event_id() -> str:
    return str(uuid.uuid4())


@dataclass
class RuntimeEvent:
    """Base class for all runtime/domain events."""

    source: str
    event_id: str = field(default_factory=_new_event_id)
    timestamp: str = field(default_factory=_utcnow)
    payload: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.payload = sanitize_payload(self.payload)


@dataclass
class RuntimeStartedEvent(RuntimeEvent):
    """Emitted once the runtime has completed its startup sequence."""
    source: str = "lifecycle_manager"


@dataclass
class RuntimeShutdownEvent(RuntimeEvent):
    """Emitted once the runtime has completed its shutdown sequence."""
    source: str = "lifecycle_manager"


@dataclass
class ServiceHealthyEvent(RuntimeEvent):
    """Emitted when a service transitions to a healthy state."""
    source: str = "health_monitor"


@dataclass
class ServiceFailedEvent(RuntimeEvent):
    """Emitted when a service failure is recorded."""
    source: str = "health_monitor"


@dataclass
class BackgroundTaskStartedEvent(RuntimeEvent):
    """Emitted when a background task is registered and started."""
    source: str = "task_registry"


@dataclass
class BackgroundTaskStoppedEvent(RuntimeEvent):
    """Emitted when a background task completes, cancels, or fails."""
    source: str = "task_registry"


@dataclass
class RecoveryTriggeredEvent(RuntimeEvent):
    """Emitted when a recovery callback is triggered for a service."""
    source: str = "recovery_manager"


@dataclass
class WatchdogAlertEvent(RuntimeEvent):
    """Emitted when the watchdog detects a stale heartbeat or dead task."""
    source: str = "watchdog"


@dataclass
class SentinelAlertEvent(RuntimeEvent):
    """Emitted when a high-severity fraud decision or security event occurs.

    This event is the primary trigger for real-time webhook notifications
    (Issue #633). When a transaction is blocked or a critical security rule
    fires, the API layer constructs and dispatches a ``SentinelAlertEvent``
    through the :class:`~src.runtime.events.dispatcher.EventDispatcher`.
    The :func:`~src.runtime.events.event_handlers.on_sentinel_alert` handler
    then routes the event to the configured Discord / Slack webhooks via
    :class:`~src.runtime.events.webhook_manager.WebhookManager`.

    Attributes
    ----------
    severity:
        Alert severity level.  Supported values: ``"LOW"``, ``"MEDIUM"``,
        ``"HIGH"``, ``"CRITICAL"``.  Defaults to ``"HIGH"``.
    title:
        Short, human-readable title for the alert card / embed.
    message:
        Detailed description of what triggered the alert.
    payload:
        Arbitrary metadata dict (transaction ID, risk score, accounts, etc.).
        Values are automatically sanitised via :func:`sanitize_payload`.
    """

    severity: str = "HIGH"
    title: str = "Sentinel Alert"
    message: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)

    # Supported severity levels for validation / documentation purposes.
    SEVERITY_LEVELS: tuple = field(
        default=("LOW", "MEDIUM", "HIGH", "CRITICAL"), init=False, repr=False, compare=False
    )
