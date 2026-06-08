"""Tests for lightweight runtime resource governance."""

from __future__ import annotations

import asyncio

from src.runtime import RecoveryManager, RuntimeHealthMonitor, RuntimeState
from src.runtime.events import EventDispatcher, RuntimeEvent, RuntimeEventBus, RuntimeStartedEvent
from src.runtime.resources import (
    BackpressureController,
    QueueBudget,
    ResourceLimits,
    RuntimeResourceManager,
    TaskBudget,
)


def _run(coro):
    return asyncio.run(coro)


class TestTaskBudget:
    def test_registration_and_deregistration(self):
        budget = TaskBudget(ResourceLimits(max_runtime_tasks=2))

        assert budget.register_task("a") is True
        assert budget.current_count == 1

        budget.unregister_task("a")
        assert budget.current_count == 0

    def test_limit_enforcement(self):
        budget = TaskBudget(ResourceLimits(max_runtime_tasks=1))

        assert budget.register_task("a") is True
        assert budget.register_task("b") is False
        assert budget.current_count == 1
        assert budget.is_exceeded() is True


class TestQueueBudget:
    def test_utilization_calculation(self):
        budget = QueueBudget(ResourceLimits(max_event_queue_size=10))

        budget.update(5)
        assert budget.current_size == 5
        assert budget.max_size == 10
        assert budget.utilization == 0.5

    def test_overload_detection(self):
        budget = QueueBudget(ResourceLimits(max_event_queue_size=2))

        budget.update(2)
        assert budget.is_overloaded() is True
        assert budget.utilization == 1.0


class TestBackpressure:
    def test_healthy_warning_throttled_transitions(self):
        controller = BackpressureController(
            ResourceLimits(max_events_per_window=2, max_recovery_attempts_per_window=2)
        )

        assert controller.can_accept_event(queue_utilization=0.1) is True
        assert controller.state == "healthy"

        assert controller.can_accept_event(queue_utilization=0.85) is True
        assert controller.state == "warning"

        assert controller.can_accept_event(queue_utilization=0.1) is False
        assert controller.state == "throttled"

    def test_recovery_throttling(self):
        controller = BackpressureController(ResourceLimits(max_recovery_attempts_per_window=1))

        assert controller.can_start_recovery() is True
        assert controller.can_start_recovery() is False
        assert controller.state == "throttled"


class TestResourceManager:
    def test_task_admission(self):
        manager = RuntimeResourceManager(ResourceLimits(max_runtime_tasks=1))

        assert manager.register_task("a") is True
        assert manager.register_task("b") is False
        manager.unregister_task("a")
        assert manager.register_task("b") is True

    def test_event_admission(self):
        manager = RuntimeResourceManager(ResourceLimits(max_events_per_window=1))

        assert manager.can_accept_event() is True
        assert manager.can_accept_event() is False

    def test_recovery_throttling(self):
        manager = RuntimeResourceManager(ResourceLimits(max_recovery_attempts_per_window=1))

        assert manager.can_start_recovery() is True
        assert manager.can_start_recovery() is False

    def test_metrics_reporting(self):
        manager = RuntimeResourceManager(ResourceLimits(max_event_queue_size=4))
        manager.register_task("task")
        manager.update_queue_size(2, 4)
        manager.can_accept_event()

        metrics = manager.get_resource_metrics()
        assert metrics["active_tasks"] == 1
        assert metrics["queue_utilization"] == 0.5
        assert metrics["backpressure_state"] == "healthy"
        assert metrics["event_rate"] == 1
        assert metrics["recovery_rate"] == 0


class TestRuntimeIntegration:
    def test_dispatcher_respects_throttling(self):
        async def _go():
            manager = RuntimeResourceManager(ResourceLimits(max_events_per_window=1))
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus, resource_manager=manager)
            received = []

            async def handler(event: RuntimeEvent):
                received.append(event)

            await bus.subscribe(RuntimeEvent, handler)
            await dispatcher.start()

            dispatcher.dispatch(RuntimeStartedEvent(source="first"))
            dispatcher.dispatch(RuntimeStartedEvent(source="throttled"))

            await asyncio.sleep(0.05)
            await dispatcher.stop()

            assert [event.source for event in received] == ["first"]
            assert manager.get_resource_metrics()["backpressure_state"] == "throttled"

        _run(_go())

    def test_recovery_manager_respects_throttling(self):
        async def _go():
            manager = RuntimeResourceManager(ResourceLimits(max_recovery_attempts_per_window=1))
            monitor = RuntimeHealthMonitor()
            monitor.register_service("svc")
            monitor.mark_failed("svc", error="failed")

            calls = []
            recovery = RecoveryManager(monitor, resource_manager=manager)
            recovery.register_recovery_callback("svc", lambda: calls.append("called"), max_attempts=3)

            assert await recovery.handle_failure("svc") is True
            assert await recovery.handle_failure("svc") is False
            assert calls == ["called"]

        _run(_go())

    def test_runtime_state_exposes_resource_metrics(self):
        state = RuntimeState()
        state.resource_manager.update_queue_size(1, state.resource_manager.limits.max_event_queue_size)

        metrics = state.get_metrics()
        assert metrics["resource_state"] == "healthy"
        assert metrics["resources"]["active_tasks"] == 0
        assert "queue_utilization" in metrics["resources"]
