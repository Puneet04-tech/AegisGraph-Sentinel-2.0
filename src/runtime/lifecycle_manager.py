"""Deterministic async startup and shutdown coordination."""

from __future__ import annotations

import asyncio
import inspect
import traceback
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, List

from ..audit import log_audit_event
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

    def _audit(self, event_type: str, severity: str = "info", **metadata: Any) -> None:
        try:
            log_audit_event(
                event_type=event_type,
                severity=severity,
                source="lifecycle_manager",
                metadata=metadata,
            )
        except Exception:
            self._logger.debug("Runtime audit recording failed", exc_info=True)

    def register_startup(self, name: str, handler: LifecycleCallable, *, critical: bool = True) -> None:
        self._startup_steps.append(LifecycleStep(name=name, handler=handler, critical=critical))

    def register_shutdown(self, name: str, handler: LifecycleCallable, *, critical: bool = False) -> None:
        self._shutdown_steps.append(LifecycleStep(name=name, handler=handler, critical=critical))

    async def startup(self) -> None:
        async with self._lock:
            if self._started:
                self._logger.info("Startup already completed", event_type="runtime_startup_already_complete")
                return

            self._logger.info(
                "Runtime startup started",
                event_type="runtime_startup_started",
                metadata={"steps": [step.name for step in self._startup_steps]},
            )
            self._audit("runtime_startup_started", steps=[step.name for step in self._startup_steps])
            self.runtime_state.shutting_down = False

            # Wire default event subscriptions to the event bus
            await register_default_subscriptions(self.runtime_state.event_bus)

            dispatcher = getattr(self.runtime_state, "dispatcher", None)
            if dispatcher is not None:
                if not dispatcher.started:
                    await dispatcher.start()
                self._logger.info("Event dispatcher started", event_type="dispatcher_started")

            completed_steps: List[str] = []
            try:
                for step in self._startup_steps:
                    await self._run_step(step, phase="startup")
                    completed_steps.append(step.name)
            except Exception as exc:
                self._logger.error(
                    f"Startup failed at step '{step.name}': {exc}",
                    event_type="runtime_startup_failed",
                    metadata={"failed_step": step.name, "completed_steps": completed_steps},
                )
                await self._rollback_startup(completed_steps)
                raise
            self._validate_runtime_services()
            self._started = True
            self.runtime_state.started = True
            self.runtime_state.record_lifecycle_event("startup_complete", steps=len(self._startup_steps))
            self._logger.info("Runtime startup complete", event_type="runtime_startup_complete")
            self._audit("runtime_startup_complete", steps=len(self._startup_steps))

            # Emit RuntimeStartedEvent after all steps succeed.
            if dispatcher is not None and dispatcher.started:
                dispatcher.dispatch(
                    RuntimeStartedEvent(
                        source="lifecycle_manager",
                        payload={"steps": len(self._startup_steps)},
                    )
                )


    def _validate_runtime_services(self) -> None:
        validator = getattr(self.runtime_state, "validate_runtime_dependencies", None)
        if validator is None:
            return
        try:
            results = validator()
        except Exception as exc:
            self._logger.warning(
                f"Runtime dependency validation failed unexpectedly: {exc}",
                event_type="runtime_dependency_validation_error",
            )
            return

        failures = [result for result in results if not getattr(result, "valid", False)]
        if failures:
            self._logger.warning(
                "Runtime dependency validation found failures",
                event_type="runtime_dependency_validation_failed",
                metadata={"failures": [failure.__dict__ for failure in failures]},
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
            self._audit("runtime_shutdown_started", steps=[step.name for step in reversed(self._shutdown_steps)])
            for step in reversed(self._shutdown_steps):
                await self._run_step(step, phase="shutdown")
            self._started = False
            self.runtime_state.started = False
            self.runtime_state.record_lifecycle_event("shutdown_complete", steps=len(self._shutdown_steps))
            self._logger.info("Runtime shutdown complete", event_type="runtime_shutdown_complete")
            self._audit("runtime_shutdown_complete", steps=len(self._shutdown_steps))

            # Emit RuntimeShutdownEvent then stop the dispatcher so it
            # drains any remaining queued events before exiting.
            if dispatcher is not None:
                if not dispatcher.started:
                    await dispatcher.start()
                dispatcher.dispatch(
                    RuntimeShutdownEvent(
                        source="lifecycle_manager",
                        payload={"steps": len(self._shutdown_steps)},
                    )
                )
                await dispatcher.stop()


    async def _rollback_startup(self, completed_steps: List[str]) -> None:
        """Tear down steps that already ran after a startup failure."""
        self._logger.warning(
            f"Rolling back {len(completed_steps)} completed startup steps",
            event_type="runtime_startup_rollback",
            metadata={"completed_steps": completed_steps},
        )
        for step in reversed(self._startup_steps):
            if step.name in completed_steps:
                try:
                    await self._run_step(step, phase="shutdown")
                except Exception as exc:
                    self._logger.error(
                        f"Rollback of step '{step.name}' failed: {exc}",
                        event_type="runtime_startup_rollback_error",
                        metadata={"step": step.name},
                    )
        dispatcher = getattr(self.runtime_state, "dispatcher", None)
        if dispatcher is not None and dispatcher.started:
            try:
                await dispatcher.stop()
            except Exception as exc:
                self._logger.error(
                    f"Dispatcher stop during rollback failed: {exc}",
                    event_type="runtime_startup_rollback_dispatcher_error",
                )
        self.runtime_state.started = False
        self._started = False

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
