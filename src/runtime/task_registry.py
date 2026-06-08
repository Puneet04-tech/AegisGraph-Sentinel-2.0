"""Centralized asyncio task tracking and cancellation."""

from __future__ import annotations

import asyncio
import inspect
import time
import traceback
import threading
from dataclasses import dataclass
from typing import Any, Awaitable, Dict, Iterable, List, Optional, Union

from ..observability import get_logger
from .events.event_types import BackgroundTaskStartedEvent, BackgroundTaskStoppedEvent

_logger = get_logger("runtime.task_registry")


@dataclass(frozen=True)
class TaskInfo:
    """Metadata for a managed background task."""

    name: str
    owner: str
    created_at: float
    done: bool
    cancelled: bool


class TaskRegistry:
    """Track background tasks so shutdown can cancel them deterministically."""

    def __init__(self, logger: Any = None, dispatcher: Optional[Any] = None) -> None:
        self._tasks: Dict[asyncio.Task, TaskInfo] = {}
        self._lock = threading.RLock()
        self._logger = logger or _logger
        self._dispatcher = dispatcher  # Optional[EventDispatcher]
        self._resource_manager = None

    def set_resource_manager(self, resource_manager: Any) -> None:
        """Attach optional resource governance without changing construction API."""
        self._resource_manager = resource_manager

    def register_task(
        self,
        task_or_coro: Union[asyncio.Task, Awaitable[Any]],
        *,
        name: str,
        owner: str = "runtime",
    ) -> asyncio.Task:
        """Register a task or coroutine and attach failure cleanup callbacks."""
        if isinstance(task_or_coro, asyncio.Task):
            task = task_or_coro
        elif inspect.isawaitable(task_or_coro):
            task = asyncio.create_task(task_or_coro, name=name)
        else:
            raise TypeError("register_task expects an asyncio.Task or awaitable")

        if self._resource_manager is not None and not self._resource_manager.register_task(task):
            if task is not task_or_coro:
                task.cancel()
            self._logger.warning(
                "Background task registration denied by resource manager",
                event_type="runtime_task_budget_denied",
                metadata={"task": name, "owner": owner},
            )
            raise RuntimeError("runtime task budget exceeded")

        info = TaskInfo(
            name=name,
            owner=owner,
            created_at=time.time(),
            done=task.done(),
            cancelled=task.cancelled(),
        )
        with self._lock:
            self._tasks[task] = info
            active_tasks = len(self._tasks)
        task.add_done_callback(self._on_task_done)
        self._logger.info(
            "Background task registered",
            event_type="runtime_task_registered",
            metadata={"task": name, "owner": owner, "active_tasks": active_tasks},
        )
        if self._dispatcher is not None:
            self._dispatcher.dispatch(
                BackgroundTaskStartedEvent(
                    source="task_registry",
                    payload={"task": name, "owner": owner},
                )
            )
        return task

    def _on_task_done(self, task: asyncio.Task) -> None:
        with self._lock:
            info = self._tasks.pop(task, None)
            active_tasks = len(self._tasks)
        if self._resource_manager is not None:
            self._resource_manager.unregister_task(task)
        if info is None:
            return

        metadata = {"task": info.name, "owner": info.owner, "active_tasks": active_tasks}
        if task.cancelled():
            self._logger.info(
                "Background task cancelled",
                event_type="runtime_task_cancelled",
                metadata=metadata,
            )
            if self._dispatcher is not None:
                self._dispatcher.dispatch(
                    BackgroundTaskStoppedEvent(
                        source="task_registry",
                        payload={"task": info.name, "owner": info.owner, "reason": "cancelled"},
                    )
                )
            return

        try:
            exc = task.exception()
        except asyncio.CancelledError:
            self._logger.info(
                "Background task cancelled",
                event_type="runtime_task_cancelled",
                metadata=metadata,
            )
            if self._dispatcher is not None:
                self._dispatcher.dispatch(
                    BackgroundTaskStoppedEvent(
                        source="task_registry",
                        payload={"task": info.name, "owner": info.owner, "reason": "cancelled"},
                    )
                )
            return

        if exc is not None:
            metadata["exception"] = repr(exc)
            metadata["traceback"] = "".join(
                traceback.format_exception(type(exc), exc, exc.__traceback__)
            )
            self._logger.error(
                "Background task failed",
                event_type="runtime_task_failed",
                metadata=metadata,
            )
            if self._dispatcher is not None:
                self._dispatcher.dispatch(
                    BackgroundTaskStoppedEvent(
                        source="task_registry",
                        payload={
                            "task": info.name,
                            "owner": info.owner,
                            "reason": "failed",
                            "error": repr(exc),
                        },
                    )
                )
        else:
            self._logger.info(
                "Background task completed",
                event_type="runtime_task_completed",
                metadata=metadata,
            )
            if self._dispatcher is not None:
                self._dispatcher.dispatch(
                    BackgroundTaskStoppedEvent(
                        source="task_registry",
                        payload={"task": info.name, "owner": info.owner, "reason": "completed"},
                    )
                )

    def unregister_task(self, task: asyncio.Task) -> None:
        """Remove a task from tracking without cancelling it."""
        with self._lock:
            self._tasks.pop(task, None)
        if self._resource_manager is not None:
            self._resource_manager.unregister_task(task)

    def get_active_tasks(self) -> List[TaskInfo]:
        """Return active task metadata for inspection and metrics."""
        with self._lock:
            items = tuple(self._tasks.items())

        active: List[TaskInfo] = []
        for task, info in items:
            if not task.done():
                active.append(
                    TaskInfo(
                        name=info.name,
                        owner=info.owner,
                        created_at=info.created_at,
                        done=task.done(),
                        cancelled=task.cancelled(),
                    )
                )
        return active

    def find_tasks_by_name(self, name: str) -> List[asyncio.Task]:
        """Return a snapshot of active tasks matching the given name."""
        with self._lock:
            return [t for t, info in list(self._tasks.items()) if info.name == name]

    @property
    def active_count(self) -> int:
        return len(self.get_active_tasks())

    async def cancel_all_tasks(
        self,
        *,
        timeout_seconds: float = 10.0,
        owners: Optional[Iterable[str]] = None,
    ) -> List[Any]:
        """Cancel managed tasks and wait for completion up to a timeout."""
        owner_filter = set(owners) if owners is not None else None
        with self._lock:
            tasks = [
                task
                for task, info in self._tasks.items()
                if not task.done() and (owner_filter is None or info.owner in owner_filter)
            ]
        if not tasks:
            self._logger.info(
                "No background tasks to cancel",
                event_type="runtime_task_cancel_all_empty",
            )
            return []

        self._logger.info(
            "Cancelling background tasks",
            event_type="runtime_task_cancel_all_started",
            metadata={"count": len(tasks), "timeout_seconds": timeout_seconds},
        )
        await asyncio.sleep(0)
        for task in tasks:
            task.cancel()

        gather_future = asyncio.gather(*tasks, return_exceptions=True)
        try:
            results = await asyncio.wait_for(asyncio.shield(gather_future), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            with self._lock:
                still_active = [
                    self._tasks[task].name
                    for task in tasks
                    if task in self._tasks and not task.done()
                ]
            self._logger.error(
                "Timed out cancelling background tasks",
                event_type="runtime_task_cancel_timeout",
                metadata={"tasks": still_active, "timeout_seconds": timeout_seconds},
            )
            return []

        self._logger.info(
            "Background task cancellation complete",
            event_type="runtime_task_cancel_all_complete",
            metadata={"cancelled": len(tasks), "active_tasks": self.active_count},
        )
        return results
