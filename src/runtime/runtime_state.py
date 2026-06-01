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


@dataclass
class RuntimeState:
    """Central runtime container attached to the legacy AppState object."""

    _max_lifecycle_events: ClassVar[int] = 1000

    services: ServiceContainer = field(default_factory=ServiceContainer)
    tasks: TaskRegistry = field(default_factory=TaskRegistry)
    health_monitor: RuntimeHealthMonitor = field(default_factory=RuntimeHealthMonitor)
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
        self.dispatcher = EventDispatcher(self._event_bus_ref())

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
                "metadata": metadata,
            }
        )

    def get_service(self, name: str, default: Any = None) -> Any:
        return self.services.get_service(name, default=default)

    def optional_service(self, name: str) -> Any:
        return self.services.optional_service(name)

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "active_task_count": self.tasks.active_count,
            "services": [info.__dict__ for info in self.services.get_initialization_state()],
            "started": self.started,
            "shutting_down": self.shutting_down,
            "lifecycle_events": len(self.lifecycle_events),
            "health_status": self.health_monitor.get_overall_status(),
        }

