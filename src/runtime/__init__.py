"""Runtime orchestration primitives for AegisGraph Sentinel."""

from .background_tasks import honeypot_auto_release_loop
from .events import EventDispatcher, RuntimeEventBus
from .lifecycle_manager import LifecycleManager
from .runtime_state import RuntimeState
from .service_container import ServiceContainer
from .task_registry import TaskInfo, TaskRegistry
from .service_health import ServiceHealth
from .health_monitor import RuntimeHealthMonitor
from .recovery_manager import RecoveryManager
from .watchdog import RuntimeWatchdog
from .resources import (
    BackpressureController,
    QueueBudget,
    ResourceLimits,
    RuntimeResourceManager,
    TaskBudget,
)

__all__ = [
    "LifecycleManager",
    "RuntimeState",
    "ServiceContainer",
    "TaskInfo",
    "TaskRegistry",
    "honeypot_auto_release_loop",
    "ServiceHealth",
    "RuntimeHealthMonitor",
    "RecoveryManager",
    "RuntimeWatchdog",
    "BackpressureController",
    "QueueBudget",
    "ResourceLimits",
    "RuntimeResourceManager",
    "TaskBudget",
    # Event infrastructure
    "RuntimeEventBus",
    "EventDispatcher",
]

