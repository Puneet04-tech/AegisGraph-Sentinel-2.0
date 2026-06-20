"""Tests for AegisGraph Sentinel 2.0 Unified Health & Self-Healing Infrastructure."""

import asyncio
import time
import pytest
from src.runtime import (
    ServiceHealth,
    RuntimeHealthMonitor,
    RecoveryManager,
    RuntimeWatchdog,
    TaskRegistry,
)


def test_health_monitor_basic():
    monitor = RuntimeHealthMonitor(unhealthy_threshold=3)

    # 1. Service registration
    monitor.register_service("test_service")
    snapshot = monitor.get_health_snapshot()
    assert "test_service" in snapshot
    assert snapshot["test_service"].status == "healthy"
    assert snapshot["test_service"].failures == 0
    assert snapshot["test_service"].restart_attempts == 0
    assert snapshot["test_service"].last_error is None

    # 2. Heartbeat updates
    first_hb = snapshot["test_service"].last_heartbeat
    time.sleep(0.01)
    monitor.mark_healthy("test_service")
    snapshot = monitor.get_health_snapshot()
    assert snapshot["test_service"].last_heartbeat > first_hb


def test_health_monitor_transitions():
    monitor = RuntimeHealthMonitor(unhealthy_threshold=3)
    monitor.register_service("test_service")

    # 3. Degraded/unhealthy transitions & failure counting
    monitor.mark_failed("test_service", error="err1")
    snapshot = monitor.get_health_snapshot()
    assert snapshot["test_service"].status == "degraded"
    assert snapshot["test_service"].failures == 1
    assert snapshot["test_service"].last_error == "err1"

    monitor.mark_failed("test_service", error="err2")
    snapshot = monitor.get_health_snapshot()
    assert snapshot["test_service"].status == "degraded"
    assert snapshot["test_service"].failures == 2
    assert snapshot["test_service"].last_error == "err2"

    monitor.mark_failed("test_service", error="err3")
    snapshot = monitor.get_health_snapshot()
    assert snapshot["test_service"].status == "unhealthy"
    assert snapshot["test_service"].failures == 3
    assert snapshot["test_service"].last_error == "err3"
    assert monitor.get_overall_status() == "unhealthy"
    monitor.increment_restart_attempts("test_service")
    assert monitor.get_health_snapshot()["test_service"].restart_attempts == 1

    # Reset back to healthy
    monitor.mark_healthy("test_service")
    snapshot = monitor.get_health_snapshot()
    assert snapshot["test_service"].status == "healthy"
    assert snapshot["test_service"].failures == 0
    assert snapshot["test_service"].restart_attempts == 0
    assert snapshot["test_service"].last_error is None
    assert monitor.get_overall_status() == "healthy"


def test_recovery_manager_execution():
    async def _run_test():
        monitor = RuntimeHealthMonitor()
        recovery = RecoveryManager(monitor)
        monitor.register_service("service_1")
        monitor.mark_failed("service_1", error="failed")

        restarted = False

        def cb():
            nonlocal restarted
            restarted = True

        # Register callback
        recovery.register_recovery_callback("service_1", cb, max_attempts=2)

        # Trigger recovery
        res = await recovery.handle_failure("service_1")
        assert res is True
        assert restarted is True

        snapshot = monitor.get_health_snapshot()
        assert snapshot["service_1"].restart_attempts == 1

        # Reset flag
        restarted = False
        res = await recovery.handle_failure("service_1")
        assert res is True
        assert restarted is True
        snapshot = monitor.get_health_snapshot()
        assert snapshot["service_1"].restart_attempts == 2

        # Exceed limit
        restarted = False
        res = await recovery.handle_failure("service_1")
        assert res is False
        assert restarted is False
        snapshot = monitor.get_health_snapshot()
        assert snapshot["service_1"].restart_attempts == 2

    asyncio.run(_run_test())


def test_watchdog_stale_heartbeat():
    async def _run_test():
        monitor = RuntimeHealthMonitor()
        registry = TaskRegistry()
        recovery = RecoveryManager(monitor)
        
        restarted = False
        def cb():
            nonlocal restarted
            restarted = True
            
        recovery.register_recovery_callback("stale_service", cb, max_attempts=2)
        monitor.register_service("stale_service")
        
        # Configure watchdog with 0.05 seconds heartbeat timeout
        watchdog = RuntimeWatchdog(
            health_monitor=monitor,
            task_registry=registry,
            recovery_manager=recovery,
            heartbeat_timeout_seconds=0.05,
        )
        
        # Artificially set last_heartbeat to the past
        monitor._services["stale_service"].last_heartbeat = time.time() - 10.0
        
        # Validate health via watchdog
        await watchdog.validate_health()
        
        # Should be marked as failed/degraded
        snapshot = monitor.get_health_snapshot()
        assert snapshot["stale_service"].status == "degraded"
        assert snapshot["stale_service"].failures == 1
        assert "Stale heartbeat" in snapshot["stale_service"].last_error
        
        # Callback should have run
        assert restarted is True

    asyncio.run(_run_test())


def test_watchdog_dead_task():
    async def _run_test():
        monitor = RuntimeHealthMonitor()
        registry = TaskRegistry()
        recovery = RecoveryManager(monitor)

        restarted = False
        def cb():
            nonlocal restarted
            restarted = True

        # Register a callback for "background_task_1"
        recovery.register_recovery_callback("background_task_1", cb, max_attempts=2)
        monitor.register_service("background_task_1")

        watchdog = RuntimeWatchdog(
            health_monitor=monitor,
            task_registry=registry,
            recovery_manager=recovery,
            heartbeat_timeout_seconds=60.0,  # no stale heartbeat
        )

        # "background_task_1" is NOT in task registry (dead task!)
        await watchdog.validate_health()

        snapshot = monitor.get_health_snapshot()
        assert snapshot["background_task_1"].status == "degraded"
        assert snapshot["background_task_1"].failures == 1
        assert "Dead task" in snapshot["background_task_1"].last_error
        assert restarted is True

    asyncio.run(_run_test())
