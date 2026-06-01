"""Deterministic async startup and shutdown coordination."""

from __future__ import annotations

import asyncio
import inspect
import traceback
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, List

from ..observability import get_logger
from .events import RuntimeShutdownEvent, RuntimeStartedEvent
from .events.subscriptions import register_default_subscriptions

LifecycleCallable = Callable[[], Any]


@dataclass(frozen=True)
class LifecycleStep:
    name: str
    handler: LifecycleCallable
    critical: bool = True


class LifecycleManager:
    """Register and run startup/shutdown steps in a controlled order."""

    def __init__(self, runtime_state: Any, logger: Any = None) -> None:
        self.runtime_state = runtime_state
        self._startup_steps: List[LifecycleStep] = []
        self._shutdown_steps: List[LifecycleStep] = []
        self._logger = logger or get_logger("runtime.lifecycle")
        self._lock = asyncio.Lock()
        self._started = False
        self._shutting_down = False

    def register_startup(self, name: str, handler: LifecycleCallable, *, critical: bool = True) -> None:
        self._startup_steps.append(LifecycleStep(name=name, handler=handler, critical=critical))

    def register_shutdown(self, name: str, handler: LifecycleCallable, *, critical: bool = False) -> None:
        self._shutdown_steps.append(LifecycleStep(name=name, handler=handler, critical=critical))

    async def startup(self) -> None:
        async with self._lock:
            if self._started:
                self._logger.info("Startup already completed", event_type="runtime_startup_already_complete")
                return

            # Start the event dispatcher and register default subscriptions
            # before running any startup steps so events emitted during
            # startup are captured.
            dispatcher = getattr(self.runtime_state, "dispatcher", None)
            event_bus = getattr(self.runtime_state, "event_bus", None)
            if dispatcher is not None:
                await dispatcher.start()
            if event_bus is not None:
                await register_default_subscriptions(event_bus)

            self._logger.info(
                "Runtime startup started",
                event_type="runtime_startup_started",
                metadata={"steps": [step.name for step in self._startup_steps]},
            )
            self.runtime_state.shutting_down = False
            for step in self._startup_steps:
                await self._run_step(step, phase="startup")
            self._started = True
            self.runtime_state.started = True
            self.runtime_state.record_lifecycle_event("startup_complete", steps=len(self._startup_steps))
            self._logger.info("Runtime startup complete", event_type="runtime_startup_complete")

            # Emit RuntimeStartedEvent after all steps succeed.
            if dispatcher is not None:
                dispatcher.dispatch(
                    RuntimeStartedEvent(
                        source="lifecycle_manager",
                        payload={"steps": len(self._startup_steps)},
                    )
                )

    async def shutdown(self) -> None:
        async with self._lock:
            if self._shutting_down:
                self._logger.info("Shutdown already in progress", event_type="runtime_shutdown_already_running")
                return
            self._shutting_down = True
            self.runtime_state.shutting_down = True

            dispatcher = getattr(self.runtime_state, "dispatcher", None)

            self._logger.info(
                "Runtime shutdown started",
                event_type="runtime_shutdown_started",
                metadata={"steps": [step.name for step in reversed(self._shutdown_steps)]},
            )
            for step in reversed(self._shutdown_steps):
                await self._run_step(step, phase="shutdown")
            self._started = False
            self.runtime_state.started = False
            self.runtime_state.record_lifecycle_event("shutdown_complete", steps=len(self._shutdown_steps))
            self._logger.info("Runtime shutdown complete", event_type="runtime_shutdown_complete")

            # Emit RuntimeShutdownEvent then stop the dispatcher so it
            # drains any remaining queued events before exiting.
            if dispatcher is not None:
                dispatcher.dispatch(
                    RuntimeShutdownEvent(
                        source="lifecycle_manager",
                        payload={"steps": len(self._shutdown_steps)},
                    )
                )
                await dispatcher.stop()

    async def _run_step(self, step: LifecycleStep, *, phase: str) -> None:
        self._logger.info(
            f"Runtime {phase} step started: {step.name}",
            event_type=f"runtime_{phase}_step_started",
            metadata={"step": step.name, "critical": step.critical},
        )
        self.runtime_state.record_lifecycle_event(f"{phase}_step_started", step=step.name)
        try:
            result = step.handler()
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            metadata = {
                "step": step.name,
                "critical": step.critical,
                "exception": repr(exc),
                "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
            }
            self._logger.error(
                f"Runtime {phase} step failed: {step.name}",
                event_type=f"runtime_{phase}_step_failed",
                metadata=metadata,
            )
            self.runtime_state.record_lifecycle_event(f"{phase}_step_failed", **metadata)
            if step.critical:
                raise
            return

        self.runtime_state.record_lifecycle_event(f"{phase}_step_complete", step=step.name)
        self._logger.info(
            f"Runtime {phase} step complete: {step.name}",
            event_type=f"runtime_{phase}_step_complete",
            metadata={"step": step.name},
        )
