"""
Comprehensive tests for the Centralized Runtime Event Bus &
Async Domain Event Processing Infrastructure.

Coverage:
  - Event bus: subscribe / unsubscribe / publish / handler isolation
  - Dispatcher: queue processing / graceful shutdown / bounded queue / thread safety
  - Runtime integration: startup, recovery, watchdog, health, task lifecycle events
  - Regression safety: existing orchestration still works end-to-end
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import List
from unittest.mock import MagicMock

import pytest

from src.runtime.events import (
    BackgroundTaskStartedEvent,
    BackgroundTaskStoppedEvent,
    EventDispatcher,
    RecoveryTriggeredEvent,
    RuntimeEvent,
    RuntimeEventBus,
    RuntimeShutdownEvent,
    RuntimeStartedEvent,
    ServiceFailedEvent,
    ServiceHealthyEvent,
    WatchdogAlertEvent,
)
from src.runtime.events.event_handlers import (
    log_event_handler,
    on_recovery_triggered,
    on_service_failed,
    on_service_healthy,
    on_watchdog_alert,
)
from src.runtime.events.subscriptions import register_default_subscriptions
from src.runtime import (
    LifecycleManager,
    RecoveryManager,
    RuntimeHealthMonitor,
    RuntimeState,
    RuntimeWatchdog,
    TaskRegistry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    """Run a coroutine in a fresh event loop."""
    return asyncio.run(coro)


# ===========================================================================
# 1. EVENT BUS UNIT TESTS
# ===========================================================================

class TestEventBusSubscribeUnsubscribe:
    def test_subscribe_and_receive_event(self):
        async def _go():
            bus = RuntimeEventBus()
            received: List[RuntimeEvent] = []

            async def handler(event: RuntimeEvent):
                received.append(event)

            await bus.subscribe(RuntimeEvent, handler)
            ev = RuntimeStartedEvent(source="test")
            await bus.publish(ev)
            assert len(received) == 1
            assert received[0] is ev

        _run(_go())

    def test_unsubscribe_stops_delivery(self):
        async def _go():
            bus = RuntimeEventBus()
            received: List[RuntimeEvent] = []

            async def handler(event):
                received.append(event)

            await bus.subscribe(RuntimeEvent, handler)
            await bus.unsubscribe(RuntimeEvent, handler)
            await bus.publish(RuntimeStartedEvent(source="test"))
            assert received == []

        _run(_go())

    def test_unsubscribe_unknown_handler_is_noop(self):
        async def _go():
            bus = RuntimeEventBus()

            async def handler(event):
                pass

            # Unsubscribing a handler that was never subscribed should not raise
            await bus.unsubscribe(RuntimeEvent, handler)

        _run(_go())

    def test_no_subscribers_publish_is_noop(self):
        async def _go():
            bus = RuntimeEventBus()
            # Should not raise
            await bus.publish(RuntimeStartedEvent(source="test"))

        _run(_go())


class TestEventBusMultiHandlerDispatch:
    def test_multiple_handlers_all_called(self):
        async def _go():
            bus = RuntimeEventBus()
            calls: List[str] = []

            async def h1(event):
                calls.append("h1")

            async def h2(event):
                calls.append("h2")

            def h3(event):
                calls.append("h3")

            await bus.subscribe(RuntimeEvent, h1)
            await bus.subscribe(RuntimeEvent, h2)
            await bus.subscribe(RuntimeEvent, h3)
            await bus.publish(RuntimeStartedEvent(source="test"))
            assert sorted(calls) == ["h1", "h2", "h3"]

        _run(_go())

    def test_subclass_matching(self):
        """A handler subscribed to the base type receives concrete subclass events."""
        async def _go():
            bus = RuntimeEventBus()
            received: List[type] = []

            async def handler(event):
                received.append(type(event))

            await bus.subscribe(RuntimeEvent, handler)
            await bus.publish(ServiceFailedEvent(source="test"))
            await bus.publish(WatchdogAlertEvent(source="test"))
            assert ServiceFailedEvent in received
            assert WatchdogAlertEvent in received

        _run(_go())

    def test_specific_type_subscription_does_not_receive_other_types(self):
        async def _go():
            bus = RuntimeEventBus()
            received: List[RuntimeEvent] = []

            async def handler(event):
                received.append(event)

            await bus.subscribe(ServiceHealthyEvent, handler)
            # Publish a different event type
            await bus.publish(ServiceFailedEvent(source="test"))
            assert received == []
            # Publish the subscribed type
            await bus.publish(ServiceHealthyEvent(source="test"))
            assert len(received) == 1

        _run(_go())


class TestEventBusHandlerIsolation:
    def test_failing_handler_does_not_prevent_other_handlers(self):
        async def _go():
            bus = RuntimeEventBus()
            second_called = []

            async def bad_handler(event):
                raise RuntimeError("intentional failure")

            async def good_handler(event):
                second_called.append(True)

            await bus.subscribe(RuntimeEvent, bad_handler)
            await bus.subscribe(RuntimeEvent, good_handler)
            # Should not raise; good_handler must still run
            await bus.publish(RuntimeStartedEvent(source="test"))
            assert second_called == [True]

        _run(_go())

    def test_failing_sync_handler_does_not_crash_bus(self):
        async def _go():
            bus = RuntimeEventBus()

            def broken(event):
                raise ValueError("sync crash")

            await bus.subscribe(RuntimeEvent, broken)
            # Must not raise
            await bus.publish(RuntimeStartedEvent(source="test"))

        _run(_go())

    def test_handler_exception_does_not_propagate_to_publisher(self):
        async def _go():
            bus = RuntimeEventBus()

            async def bad(event):
                raise Exception("boom")

            await bus.subscribe(RuntimeEvent, bad)
            # Publisher must receive no exception
            try:
                await bus.publish(RuntimeStartedEvent(source="test"))
            except Exception as exc:
                pytest.fail(f"publish raised unexpectedly: {exc}")

        _run(_go())


class TestEventBusAsyncHandlers:
    def test_async_handler_is_awaited(self):
        async def _go():
            bus = RuntimeEventBus()
            done = asyncio.Event()

            async def async_handler(event):
                await asyncio.sleep(0)
                done.set()

            await bus.subscribe(RuntimeEvent, async_handler)
            await bus.publish(RuntimeStartedEvent(source="test"))
            assert done.is_set()

        _run(_go())


# ===========================================================================
# 2. DISPATCHER UNIT TESTS
# ===========================================================================

class TestDispatcherQueueProcessing:
    def test_dispatched_events_are_delivered_to_bus(self):
        async def _go():
            bus = RuntimeEventBus()
            received: List[RuntimeEvent] = []

            async def handler(event):
                received.append(event)

            await bus.subscribe(RuntimeEvent, handler)
            dispatcher = EventDispatcher(bus)
            await dispatcher.start()

            dispatcher.dispatch(RuntimeStartedEvent(source="test"))
            dispatcher.dispatch(RuntimeShutdownEvent(source="test"))

            # Allow the dispatch loop to process events
            await asyncio.sleep(0.05)
            await dispatcher.stop()

            assert len(received) == 2
            assert any(isinstance(e, RuntimeStartedEvent) for e in received)
            assert any(isinstance(e, RuntimeShutdownEvent) for e in received)

        _run(_go())

    def test_dispatch_before_start_is_ignored(self):
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            # Not started — dispatch should silently do nothing
            dispatcher.dispatch(RuntimeStartedEvent(source="test"))

        _run(_go())


class TestDispatcherGracefulShutdown:
    def test_stop_drains_remaining_events(self):
        async def _go():
            bus = RuntimeEventBus()
            received: List[RuntimeEvent] = []

            async def handler(event):
                received.append(event)

            await bus.subscribe(RuntimeEvent, handler)
            dispatcher = EventDispatcher(bus)
            await dispatcher.start()

            for _ in range(10):
                dispatcher.dispatch(RuntimeStartedEvent(source="test"))

            await dispatcher.stop()
            # All events should have been processed before stop returns
            assert len(received) == 10

        _run(_go())

    def test_stop_when_not_started_is_noop(self):
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            # Should not raise
            await dispatcher.stop()

        _run(_go())

    def test_double_start_is_idempotent(self):
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            await dispatcher.start()
            await dispatcher.start()  # Second start should be a no-op
            await dispatcher.stop()

        _run(_go())


class TestDispatcherBoundedQueue:
    def test_full_queue_drops_event_and_logs_warning(self):
        received: List[RuntimeEvent] = []

        async def _go():
            bus = RuntimeEventBus()
            slow_started = asyncio.Event()
            release = asyncio.Event()

            async def slow_handler(event):
                slow_started.set()
                await release.wait()

            async def tracking_handler(event):
                received.append(event)

            await bus.subscribe(RuntimeEvent, slow_handler)
            await bus.subscribe(RuntimeEvent, tracking_handler)

            # maxsize=1: queue holds exactly one pending event
            dispatcher = EventDispatcher(bus, maxsize=1)
            await dispatcher.start()

            # Dispatch first event — the loop dequeues it immediately and
            # enters slow_handler, leaving the queue empty.
            dispatcher.dispatch(RuntimeStartedEvent(source="first"))
            await slow_started.wait()

            # Now queue is empty and slow_handler is blocking.
            # Fill the single slot.
            dispatcher.dispatch(RuntimeStartedEvent(source="fill"))

            # This one should be dropped because the queue is now full.
            dispatcher.dispatch(RuntimeStartedEvent(source="overflow"))

            release.set()
            await dispatcher.stop()

        _run(_go())

        # The key invariant: the overflow event was dropped (never delivered),
        # and the dispatcher shut down cleanly without crashing.
        sources = [e.source for e in received]
        assert "overflow" not in sources, "overflow event should have been dropped by bounded queue"
        assert "first" in sources, "first event should have been delivered"
        # Dispatcher completed stop() without error — bounded queue did not crash it


class TestDispatcherThreadSafety:
    def test_dispatch_from_background_thread_is_safe(self):
        async def _go():
            bus = RuntimeEventBus()
            received: List[RuntimeEvent] = []
            lock = threading.Lock()

            async def handler(event):
                with lock:
                    received.append(event)

            await bus.subscribe(RuntimeEvent, handler)
            dispatcher = EventDispatcher(bus)
            await dispatcher.start()

            loop = asyncio.get_running_loop()

            def thread_worker():
                for _ in range(20):
                    # Call dispatch from a background thread
                    loop.call_soon_threadsafe(
                        dispatcher.dispatch,
                        RuntimeStartedEvent(source="thread"),
                    )

            t = threading.Thread(target=thread_worker)
            t.start()
            t.join()
            await asyncio.sleep(0.1)
            await dispatcher.stop()
            assert len(received) == 20

        _run(_go())


# ===========================================================================
# 3. RUNTIME INTEGRATION TESTS
# ===========================================================================

class TestStartupEventEmission:
    def test_runtime_started_event_emitted_on_successful_startup(self):
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            received: List[RuntimeEvent] = []

            async def handler(event):
                received.append(event)

            await state.event_bus.subscribe(RuntimeStartedEvent, handler)
            await lifecycle.startup()
            # Give dispatcher a moment to deliver the event
            await asyncio.sleep(0.05)
            await lifecycle.shutdown()

            assert any(isinstance(e, RuntimeStartedEvent) for e in received)

        _run(_go())

    def test_runtime_shutdown_event_emitted_on_shutdown(self):
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            received: List[RuntimeEvent] = []

            async def handler(event):
                received.append(event)

            await state.event_bus.subscribe(RuntimeShutdownEvent, handler)
            await lifecycle.startup()
            await lifecycle.shutdown()

            assert any(isinstance(e, RuntimeShutdownEvent) for e in received)

        _run(_go())

    def test_dispatcher_starts_with_lifecycle_and_stops_on_shutdown(self):
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)

            await lifecycle.startup()
            assert state.dispatcher._running is True

            await lifecycle.shutdown()
            assert state.dispatcher._running is False

        _run(_go())


class TestHealthEventEmission:
    def test_service_healthy_event_dispatched(self):
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            await dispatcher.start()

            received: List[RuntimeEvent] = []

            async def handler(event):
                received.append(event)

            await bus.subscribe(ServiceHealthyEvent, handler)

            monitor = RuntimeHealthMonitor(dispatcher=dispatcher)
            monitor.register_service("svc_a")
            monitor.mark_healthy("svc_a")

            await asyncio.sleep(0.05)
            await dispatcher.stop()

            assert any(
                isinstance(e, ServiceHealthyEvent) and e.payload.get("service") == "svc_a"
                for e in received
            )

        _run(_go())

    def test_service_failed_event_dispatched(self):
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            await dispatcher.start()

            received: List[RuntimeEvent] = []

            async def handler(event):
                received.append(event)

            await bus.subscribe(ServiceFailedEvent, handler)

            monitor = RuntimeHealthMonitor(dispatcher=dispatcher)
            monitor.register_service("svc_b")
            monitor.mark_failed("svc_b", error="test error")

            await asyncio.sleep(0.05)
            await dispatcher.stop()

            assert any(
                isinstance(e, ServiceFailedEvent) and e.payload.get("service") == "svc_b"
                for e in received
            )

        _run(_go())

    def test_no_event_when_no_dispatcher(self):
        """Health monitor without a dispatcher must work exactly as before."""
        monitor = RuntimeHealthMonitor()
        monitor.register_service("svc")
        monitor.mark_healthy("svc")
        monitor.mark_failed("svc", error="err")
        snap = monitor.get_health_snapshot()
        assert snap["svc"].status == "degraded"


class TestTaskLifecycleEventEmission:
    def test_task_started_event_dispatched(self):
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            await dispatcher.start()

            received: List[RuntimeEvent] = []

            async def handler(event):
                received.append(event)

            await bus.subscribe(BackgroundTaskStartedEvent, handler)

            registry = TaskRegistry(dispatcher=dispatcher)

            async def worker():
                return "done"

            task = registry.register_task(worker(), name="my_task", owner="test")
            await task

            await asyncio.sleep(0.05)
            await dispatcher.stop()

            assert any(
                isinstance(e, BackgroundTaskStartedEvent) and e.payload.get("task") == "my_task"
                for e in received
            )

        _run(_go())

    def test_task_stopped_event_dispatched_on_completion(self):
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            await dispatcher.start()

            received: List[RuntimeEvent] = []

            async def handler(event):
                received.append(event)

            await bus.subscribe(BackgroundTaskStoppedEvent, handler)

            registry = TaskRegistry(dispatcher=dispatcher)

            async def worker():
                return "done"

            task = registry.register_task(worker(), name="finish_task", owner="test")
            await task
            await asyncio.sleep(0.05)
            await dispatcher.stop()

            stopped = [
                e for e in received
                if isinstance(e, BackgroundTaskStoppedEvent)
                and e.payload.get("task") == "finish_task"
            ]
            assert stopped
            assert stopped[0].payload["reason"] == "completed"

        _run(_go())

    def test_task_stopped_event_dispatched_on_cancel(self):
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            await dispatcher.start()

            received: List[RuntimeEvent] = []

            async def handler(event):
                received.append(event)

            await bus.subscribe(BackgroundTaskStoppedEvent, handler)
            registry = TaskRegistry(dispatcher=dispatcher)

            async def long_worker():
                await asyncio.sleep(60)

            registry.register_task(long_worker(), name="cancel_task", owner="test")
            await registry.cancel_all_tasks(timeout_seconds=1)
            await asyncio.sleep(0.05)
            await dispatcher.stop()

            stopped = [
                e for e in received
                if isinstance(e, BackgroundTaskStoppedEvent)
                and e.payload.get("task") == "cancel_task"
            ]
            assert stopped
            assert stopped[0].payload["reason"] == "cancelled"

        _run(_go())


class TestRecoveryEventEmission:
    def test_recovery_triggered_event_dispatched(self):
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            await dispatcher.start()

            received: List[RuntimeEvent] = []

            async def handler(event):
                received.append(event)

            await bus.subscribe(RecoveryTriggeredEvent, handler)

            monitor = RuntimeHealthMonitor()
            monitor.register_service("svc_r")
            monitor.mark_failed("svc_r", error="failure")

            recovery = RecoveryManager(monitor, dispatcher=dispatcher)
            recovery.register_recovery_callback("svc_r", lambda: None, max_attempts=3)

            await recovery.handle_failure("svc_r")
            await asyncio.sleep(0.05)
            await dispatcher.stop()

            assert any(
                isinstance(e, RecoveryTriggeredEvent)
                and e.payload.get("service") == "svc_r"
                for e in received
            )

        _run(_go())


class TestWatchdogEventEmission:
    def test_watchdog_stale_heartbeat_emits_alert_event(self):
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            await dispatcher.start()

            received: List[RuntimeEvent] = []

            async def handler(event):
                received.append(event)

            await bus.subscribe(WatchdogAlertEvent, handler)

            monitor = RuntimeHealthMonitor()
            registry = TaskRegistry()
            watchdog = RuntimeWatchdog(
                health_monitor=monitor,
                task_registry=registry,
                heartbeat_timeout_seconds=0.01,
                dispatcher=dispatcher,
            )

            monitor.register_service("stale_svc")
            # Force stale heartbeat
            monitor._services["stale_svc"].last_heartbeat = time.time() - 10.0

            await watchdog.validate_health()
            await asyncio.sleep(0.05)
            await dispatcher.stop()

            alerts = [
                e for e in received
                if isinstance(e, WatchdogAlertEvent)
                and e.payload.get("alert_type") == "stale_heartbeat"
            ]
            assert alerts
            assert alerts[0].payload["target"] == "stale_svc"

        _run(_go())

    def test_watchdog_dead_task_emits_alert_event(self):
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            await dispatcher.start()

            received: List[RuntimeEvent] = []

            async def handler(event):
                received.append(event)

            await bus.subscribe(WatchdogAlertEvent, handler)

            monitor = RuntimeHealthMonitor()
            registry = TaskRegistry()
            recovery = RecoveryManager(monitor)
            watchdog = RuntimeWatchdog(
                health_monitor=monitor,
                task_registry=registry,
                recovery_manager=recovery,
                heartbeat_timeout_seconds=60.0,
                dispatcher=dispatcher,
            )

            monitor.register_service("dead_task")
            recovery.register_recovery_callback("dead_task", lambda: None, max_attempts=2)

            await watchdog.validate_health()
            await asyncio.sleep(0.05)
            await dispatcher.stop()

            alerts = [
                e for e in received
                if isinstance(e, WatchdogAlertEvent)
                and e.payload.get("alert_type") == "dead_task"
            ]
            assert alerts
            assert alerts[0].payload["target"] == "dead_task"

        _run(_go())


class TestDefaultSubscriptions:
    def test_register_default_subscriptions_wires_handlers(self):
        async def _go():
            bus = RuntimeEventBus()
            await register_default_subscriptions(bus)

            # After registration, the base-type log handler should be present
            # and fire without error on any event type.
            await bus.publish(RuntimeStartedEvent(source="test"))
            await bus.publish(ServiceHealthyEvent(source="test", payload={"service": "x"}))
            await bus.publish(ServiceFailedEvent(
                source="test", payload={"service": "x", "status": "degraded", "failures": 1}
            ))
            await bus.publish(RecoveryTriggeredEvent(
                source="test", payload={"service": "x", "attempt": 1, "max_attempts": 3}
            ))
            await bus.publish(WatchdogAlertEvent(
                source="test", payload={"alert_type": "stale_heartbeat", "target": "x"}
            ))

        _run(_go())


# ===========================================================================
# 4. REGRESSION SAFETY — existing runtime orchestration still works
# ===========================================================================

class TestRegressionLifecycleOrchestration:
    def test_startup_and_shutdown_still_work_end_to_end(self):
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            events = []

            lifecycle.register_startup("s1", lambda: events.append("startup:s1"))
            lifecycle.register_startup("s2", lambda: events.append("startup:s2"))
            lifecycle.register_shutdown("s1", lambda: events.append("shutdown:s1"))
            lifecycle.register_shutdown("s2", lambda: events.append("shutdown:s2"))

            await lifecycle.startup()
            await lifecycle.shutdown()

            assert events == [
                "startup:s1", "startup:s2",
                "shutdown:s2", "shutdown:s1",
            ]
            assert state.started is False
            assert state.shutting_down is True

        _run(_go())

    def test_optional_startup_step_failure_continues(self):
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            reached = []

            lifecycle.register_startup("bad", lambda: (_ for _ in ()).throw(RuntimeError("fail")), critical=False)
            lifecycle.register_startup("good", lambda: reached.append("good"))

            await lifecycle.startup()
            assert reached == ["good"]
            await lifecycle.shutdown()

        _run(_go())

    def test_concurrent_startup_is_idempotent(self):
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            count = 0

            async def once():
                nonlocal count
                await asyncio.sleep(0)
                count += 1

            lifecycle.register_startup("once", once)
            await asyncio.gather(lifecycle.startup(), lifecycle.startup())
            assert count == 1
            assert state.started is True
            await lifecycle.shutdown()

        _run(_go())


class TestRegressionTaskRegistry:
    def test_tasks_cancel_cleanly_with_dispatcher(self):
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            await dispatcher.start()

            registry = TaskRegistry(dispatcher=dispatcher)
            cancelled = asyncio.Event()

            async def worker():
                try:
                    await asyncio.sleep(60)
                except asyncio.CancelledError:
                    cancelled.set()
                    raise

            registry.register_task(worker(), name="worker", owner="test")
            await registry.cancel_all_tasks(timeout_seconds=1)
            assert cancelled.is_set()
            await asyncio.sleep(0)
            assert registry.active_count == 0
            await dispatcher.stop()

        _run(_go())


class TestRegressionHealthMonitor:
    def test_health_transitions_still_accurate_with_dispatcher(self):
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            await dispatcher.start()

            monitor = RuntimeHealthMonitor(unhealthy_threshold=3, dispatcher=dispatcher)
            monitor.register_service("svc")
            assert monitor.get_health_snapshot()["svc"].status == "healthy"

            monitor.mark_failed("svc", error="e1")
            monitor.mark_failed("svc", error="e2")
            monitor.mark_failed("svc", error="e3")
            assert monitor.get_health_snapshot()["svc"].status == "unhealthy"

            monitor.mark_healthy("svc")
            assert monitor.get_health_snapshot()["svc"].status == "healthy"
            assert monitor.get_health_snapshot()["svc"].failures == 0

            await dispatcher.stop()

        _run(_go())


class TestRegressionWatchdog:
    def test_watchdog_still_detects_stale_heartbeat_and_triggers_recovery(self):
        async def _go():
            monitor = RuntimeHealthMonitor()
            registry = TaskRegistry()
            recovery = RecoveryManager(monitor)

            restarted = False

            def cb():
                nonlocal restarted
                restarted = True

            recovery.register_recovery_callback("svc", cb, max_attempts=2)
            monitor.register_service("svc")
            monitor._services["svc"].last_heartbeat = time.time() - 100.0

            watchdog = RuntimeWatchdog(
                health_monitor=monitor,
                task_registry=registry,
                recovery_manager=recovery,
                heartbeat_timeout_seconds=1.0,
            )

            await watchdog.validate_health()
            assert monitor.get_health_snapshot()["svc"].status == "degraded"
            assert restarted is True

        _run(_go())


class TestEventTypeFields:
    def test_event_id_is_unique_per_instance(self):
        e1 = RuntimeStartedEvent(source="a")
        e2 = RuntimeStartedEvent(source="a")
        assert e1.event_id != e2.event_id

    def test_timestamp_is_present_and_utc(self):
        e = RuntimeStartedEvent(source="a")
        assert "T" in e.timestamp
        assert e.timestamp.endswith("Z")

    def test_payload_defaults_to_empty_dict(self):
        e = RuntimeStartedEvent(source="a")
        assert e.payload == {}

    def test_payload_can_carry_arbitrary_data(self):
        e = ServiceFailedEvent(source="monitor", payload={"service": "x", "failures": 3})
        assert e.payload["service"] == "x"
        assert e.payload["failures"] == 3