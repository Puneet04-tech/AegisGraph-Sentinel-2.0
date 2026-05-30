"""Tests for centralized runtime orchestration and lifecycle safety."""

import asyncio
import logging
from contextlib import contextmanager

import pytest

from src.runtime import LifecycleManager, RuntimeState, ServiceContainer, TaskRegistry


@contextmanager
def _capture_aegis_logs(caplog, logger_name):
    logger = logging.getLogger(logger_name)
    caplog.set_level(logging.INFO, logger=logger_name)
    logger.addHandler(caplog.handler)
    try:
        yield
    finally:
        logger.removeHandler(caplog.handler)


def test_service_container_registration_and_optional_lookup():
    container = ServiceContainer()
    service = object()

    assert container.register_service("example", service) is service
    assert container.get_service("example") is service
    assert container.optional_service("missing") is None
    assert container.get_service("missing", default="fallback") == "fallback"

    state = container.get_initialization_state()
    assert state[0].name == "example"
    assert state[0].initialized is True


def test_service_container_required_missing_raises():
    container = ServiceContainer()
    with pytest.raises(KeyError):
        container.get_service("missing", required=True)


def test_runtime_state_isolation_and_metrics():
    runtime_state = RuntimeState()
    legacy_state = object()

    runtime_state.bind_legacy_state(legacy_state)
    runtime_state.record_lifecycle_event("unit_test", ok=True)

    assert runtime_state.get_service("app_state") is legacy_state
    metrics = runtime_state.get_metrics()
    assert metrics["active_task_count"] == 0
    assert metrics["lifecycle_events"] == 1


def test_runtime_state_lifecycle_events_are_bounded(monkeypatch):
    monkeypatch.setattr(RuntimeState, "_max_lifecycle_events", 3)

    runtime_state = RuntimeState()
    for index in range(5):
        runtime_state.record_lifecycle_event("unit_test", index=index)

    assert len(runtime_state.lifecycle_events) == 3
    assert [event["metadata"]["index"] for event in runtime_state.lifecycle_events] == [2, 3, 4]


def test_task_registry_registers_and_cleans_completed_tasks():
    async def _run():
        registry = TaskRegistry()

        async def worker():
            return "done"

        task = registry.register_task(worker(), name="worker", owner="test")
        assert registry.active_count == 1
        assert [info.name for info in registry.get_active_tasks()] == ["worker"]
        assert await task == "done"
        await asyncio.sleep(0)
        assert registry.active_count == 0

    asyncio.run(_run())


def test_task_registry_gracefully_cancels_tasks():
    async def _run():
        registry = TaskRegistry()
        cancelled = asyncio.Event()

        async def worker():
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                cancelled.set()
                raise

        registry.register_task(worker(), name="sleeping_worker", owner="test")
        assert registry.active_count == 1
        await registry.cancel_all_tasks(timeout_seconds=1)
        assert cancelled.is_set()
        await asyncio.sleep(0)
        assert registry.active_count == 0

    asyncio.run(_run())


def test_task_registry_handles_mutation_during_shutdown():
    async def _run():
        registry = TaskRegistry()
        cleanup_started = asyncio.Event()

        async def cleanup_worker():
            cleanup_started.set()
            await asyncio.sleep(60)

        async def worker():
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                registry.register_task(cleanup_worker(), name="cleanup_worker", owner="test")
                raise

        task = registry.register_task(worker(), name="primary_worker", owner="test")
        await registry.cancel_all_tasks(timeout_seconds=1)
        await asyncio.sleep(0)

        assert cleanup_started.is_set()
        assert registry.active_count == 1

        await registry.cancel_all_tasks(timeout_seconds=1)
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.sleep(0)
        assert registry.active_count == 0

    asyncio.run(_run())


def test_task_registry_cancellation_timeout_logs(caplog):
    async def _run():
        registry = TaskRegistry()
        release = asyncio.Event()

        async def stubborn_worker():
            while True:
                try:
                    await asyncio.sleep(60)
                except asyncio.CancelledError:
                    if release.is_set():
                        raise
                    await release.wait()

        task = registry.register_task(stubborn_worker(), name="stubborn_worker", owner="test")
        await registry.cancel_all_tasks(timeout_seconds=0.01)
        release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return task

    with _capture_aegis_logs(caplog, "aegis.runtime.task_registry"):
        task = asyncio.run(_run())

    assert task.done()
    assert any("runtime_task_cancel_timeout" in record.message for record in caplog.records)


def test_background_task_failure_is_logged(caplog):
    async def _run():
        registry = TaskRegistry()

        async def worker():
            raise RuntimeError("boom")

        task = registry.register_task(worker(), name="failing_worker", owner="test")
        with pytest.raises(RuntimeError):
            await task
        await asyncio.sleep(0)

    with _capture_aegis_logs(caplog, "aegis.runtime.task_registry"):
        asyncio.run(_run())

    assert any("runtime_task_failed" in record.message for record in caplog.records)
    assert any("boom" in record.message for record in caplog.records)
    assert any("traceback" in record.message for record in caplog.records)


def test_lifecycle_manager_runs_startup_in_order_and_shutdown_reverse():
    async def _run():
        runtime_state = RuntimeState()
        lifecycle = LifecycleManager(runtime_state)
        events = []

        lifecycle.register_startup("first", lambda: events.append("startup:first"))
        lifecycle.register_startup("second", lambda: events.append("startup:second"))
        lifecycle.register_shutdown("first", lambda: events.append("shutdown:first"))
        lifecycle.register_shutdown("second", lambda: events.append("shutdown:second"))

        await lifecycle.startup()
        await lifecycle.shutdown()

        assert events == [
            "startup:first",
            "startup:second",
            "shutdown:second",
            "shutdown:first",
        ]
        assert runtime_state.started is False
        assert runtime_state.shutting_down is True

    asyncio.run(_run())


def test_lifecycle_optional_startup_failure_continues(caplog):
    async def _run():
        runtime_state = RuntimeState()
        lifecycle = LifecycleManager(runtime_state)
        events = []

        def optional_failure():
            raise RuntimeError("optional failed")

        lifecycle.register_startup("optional", optional_failure, critical=False)
        lifecycle.register_startup("next", lambda: events.append("next"))

        await lifecycle.startup()
        assert events == ["next"]

    with _capture_aegis_logs(caplog, "aegis.runtime.lifecycle"):
        asyncio.run(_run())

    assert any("runtime_startup_step_failed" in record.message for record in caplog.records)


def test_lifecycle_critical_startup_failure_raises():
    async def _run():
        runtime_state = RuntimeState()
        lifecycle = LifecycleManager(runtime_state)
        lifecycle.register_startup("critical", lambda: (_ for _ in ()).throw(RuntimeError("critical failed")))
        with pytest.raises(RuntimeError, match="critical failed"):
            await lifecycle.startup()

    asyncio.run(_run())


def test_lifecycle_concurrent_startup_is_idempotent():
    async def _run():
        runtime_state = RuntimeState()
        lifecycle = LifecycleManager(runtime_state)
        count = 0

        async def startup_step():
            nonlocal count
            await asyncio.sleep(0)
            count += 1

        lifecycle.register_startup("once", startup_step)
        await asyncio.gather(lifecycle.startup(), lifecycle.startup())
        assert count == 1
        assert runtime_state.started is True

    asyncio.run(_run())
