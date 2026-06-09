"""Controlled runtime state for shared app resources."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar, Deque, Dict, Optional

from .events import EventDispatcher, RuntimeEventBus
from .service_container import ServiceContainer
from .task_registry import TaskRegistry
from .health_monitor import RuntimeHealthMonitor
from .resources import RuntimeResourceManager
from ..security import sanitize_metadata
from ..audit import log_audit_event
from ..configuration import ConfigRegistry, ConfigReloadManager, ConfigSnapshot


@dataclass
class RuntimeState:
    """Central runtime container attached to the legacy AppState object."""

    _max_lifecycle_events: ClassVar[int] = 1000

    services: ServiceContainer = field(default_factory=ServiceContainer)
    tasks: TaskRegistry = field(default_factory=TaskRegistry)
    health_monitor: RuntimeHealthMonitor = field(default_factory=RuntimeHealthMonitor)
    resource_manager: RuntimeResourceManager = field(default_factory=RuntimeResourceManager)
    config_registry: ConfigRegistry = field(default_factory=ConfigRegistry)
    config_reload_manager: ConfigReloadManager = field(init=False)
    recovery_manager: Optional[Any] = None
    watchdog: Optional[Any] = None
    legacy_state: Optional[Any] = None
    started: bool = False
    shutting_down: bool = False
    lifecycle_events: Deque[Dict[str, Any]] = field(init=False)

    # ── Event infrastructure ────────────────────────────────────────────
    event_bus: RuntimeEventBus = field(default_factory=RuntimeEventBus)
    dispatcher: EventDispatcher = field(init=False)

    def __post_init__(self) -> None:
        self.lifecycle_events = deque(maxlen=self._max_lifecycle_events)
        self.dispatcher = EventDispatcher(
            self._event_bus_ref(),
            maxsize=self.resource_manager.limits.max_event_queue_size,
            resource_manager=self.resource_manager,
        )
        self.tasks.set_resource_manager(self.resource_manager)
        self.config_reload_manager = ConfigReloadManager(self.config_registry, audit_logger=log_audit_event)
        self.resource_manager.set_config_registry(self.config_registry)
        self.health_monitor.set_config_registry(self.config_registry)
        self.services.register_service("resource_manager", self.resource_manager, replace=True)
        self.services.register_service("config_registry", self.config_registry, replace=True)
        self.services.register_service("config_reload_manager", self.config_reload_manager, replace=True)

    def set_recovery_manager(self, recovery_manager: Any) -> None:
        self.recovery_manager = recovery_manager
        if hasattr(recovery_manager, "set_config_registry"):
            recovery_manager.set_config_registry(self.config_registry)
        self.services.register_service("recovery_manager", recovery_manager, replace=True)

    # EventDispatcher needs a reference to the event_bus field.  Using a
    # helper avoids capturing 'self' in a lambda stored on self before the
    # dataclass is fully constructed.
    def _event_bus_ref(self) -> RuntimeEventBus:
        return self.event_bus

    def bind_legacy_state(self, state: Any) -> None:
        self.legacy_state = state
        self.services.register_service("app_state", state, replace=True)

    def record_lifecycle_event(self, event_type: str, **metadata: Any) -> None:
        self.lifecycle_events.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "event_type": event_type,
                "metadata": sanitize_metadata(metadata),
            }
        )

    def get_service(self, name: str, default: Any = None) -> Any:
        return self.services.get_service(name, default=default)

    def optional_service(self, name: str) -> Any:
        return self.services.optional_service(name)

    def get_metrics(self) -> Dict[str, Any]:
        resource_metrics = self.resource_manager.get_resource_metrics()
        config_snapshot = ConfigSnapshot.capture(self.config_registry)
        return {
            "active_task_count": self.tasks.active_count,
            "services": [info.__dict__ for info in self.services.get_initialization_state()],
            "started": self.started,
            "shutting_down": self.shutting_down,
            "lifecycle_events": len(self.lifecycle_events),
            "health_status": self.health_monitor.get_overall_status(),
            "resource_state": resource_metrics["backpressure_state"],
            "resources": resource_metrics,
            "configuration": {
                "count": len(config_snapshot.values),
                "snapshot_timestamp": config_snapshot.timestamp,
                "names": sorted(config_snapshot.values.keys()),
            },
        }

