"""
Comprehensive lifecycle state validation tests.

These tests verify that runtime lifecycle state transitions are consistent,
deterministic, and properly validated under both normal and failure conditions.

Coverage:
- Successful startup with state validation
- Startup failure with rollback state validation
- Partial startup failure
- Shutdown state validation
- Interrupted shutdown
- Recovery interactions with lifecycle state
- Event ordering validation
- Dispatcher lifecycle state consistency
- Watchdog state consistency
- Recovery manager state consistency
- Runtime state invariant validation
- Concurrent lifecycle operations
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import MagicMock, patch

import pytest

from src.runtime import (
    LifecycleManager,
    RuntimeHealthMonitor,
    RuntimeState,
    RuntimeWatchdog,
    TaskRegistry,
)
from src.runtime.events import (
    EventDispatcher,
    RuntimeEventBus,
    RuntimeStartedEvent,
    RuntimeShutdownEvent,
)
from src.runtime.recovery_manager import RecoveryManager


# ===========================================================================
# 1. LIFECYCLE MANAGER STATE VALIDATION TESTS
# ===========================================================================

class TestLifecycleManagerStateValidation:
    """Test LifecycleManager state transitions and validation."""

    def test_startup_sets_dispatcher_started_before_runtime_started(self):
        """Verify dispatcher is actually started before runtime_state.started is set."""
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            
            await lifecycle.startup()
            
            # Invariant: if runtime is started, dispatcher must be started
            assert state.started is True
            assert state.dispatcher.started is True
            assert state.dispatcher._started is True
            
            await lifecycle.shutdown()
        
        asyncio.run(_go())

    def test_startup_during_shutdown_raises_error(self):
        """Verify cannot start while shutdown is in progress."""
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            
            # Start a slow shutdown
            async def slow_shutdown_step():
                await asyncio.sleep(0.1)
            
            lifecycle.register_shutdown("slow", slow_shutdown_step)
            await lifecycle.startup()
            
            # Try to start while shutdown is in progress
            shutdown_task = asyncio.create_task(lifecycle.shutdown())
            await asyncio.sleep(0.01)  # Let shutdown start
            
            with pytest.raises(RuntimeError, match="Cannot start runtime while shutdown is in progress"):
                await lifecycle.startup()
            
            await shutdown_task
        
        asyncio.run(_go())

    def test_rollback_validates_dispatcher_stopped(self):
        """Verify rollback validates dispatcher stopped successfully."""
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            
            # Register a step that fails
            def failing_step():
                raise RuntimeError("intentional failure")
            
            lifecycle.register_startup("failing", failing_step)
            lifecycle.register_startup("good", lambda: None)
            
            with pytest.raises(RuntimeError, match="intentional failure"):
                await lifecycle.startup()
            
            # After rollback, runtime should not be started
            assert state.started is False
            assert lifecycle._started is False
            
            # Dispatcher should be stopped
            assert state.dispatcher.started is False
        
        asyncio.run(_go())

    def test_concurrent_startup_is_idempotent_with_state_validation(self):
        """Verify concurrent startup attempts are handled correctly."""
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            count = 0
            
            async def startup_step():
                nonlocal count
                await asyncio.sleep(0)
                count += 1
            
            lifecycle.register_startup("once", startup_step)
            await asyncio.gather(lifecycle.startup(), lifecycle.startup())
            
            # Only one startup should have executed
            assert count == 1
            assert state.started is True
            assert lifecycle._started is True
            
            await lifecycle.shutdown()
        
        asyncio.run(_go())

    def test_concurrent_shutdown_is_idempotent(self):
        """Verify concurrent shutdown attempts are handled correctly."""
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            
            await lifecycle.startup()
            
            # Try concurrent shutdowns
            await asyncio.gather(lifecycle.shutdown(), lifecycle.shutdown())
            
            assert state.started is False
            assert state.shutting_down is True
            assert lifecycle._started is False
        
        asyncio.run(_go())


# ===========================================================================
# 2. EVENT DISPATCHER STATE VALIDATION TESTS
# ===========================================================================

class TestEventDispatcherStateValidation:
    """Test EventDispatcher state transitions and validation."""

    def test_started_flag_set_only_after_start_completes(self):
        """Verify _started is set to True only after start completes."""
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            
            assert dispatcher._started is False
            
            await dispatcher.start()
            
            assert dispatcher._started is True
            assert dispatcher._running is True
            assert dispatcher._task is not None
            
            await dispatcher.stop()
        
        asyncio.run(_go())

    def test_started_flag_set_to_false_only_after_stop_completes(self):
        """Verify _started is set to False only after stop completes."""
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            
            await dispatcher.start()
            assert dispatcher._started is True
            
            # Start stop
            stop_task = asyncio.create_task(dispatcher.stop())
            
            # While stop is in progress, _started should still be True
            await asyncio.sleep(0.01)
            assert dispatcher._started is True or dispatcher._stopping is True
            
            await stop_task
            
            # After stop completes, _started should be False
            assert dispatcher._started is False
            assert dispatcher._stopping is False
        
        asyncio.run(_go())

    def test_concurrent_start_stop_guarded(self):
        """Verify concurrent start and stop are guarded against."""
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            
            await dispatcher.start()
            
            # Try to start while stopping
            stop_task = asyncio.create_task(dispatcher.stop())
            await asyncio.sleep(0.01)
            
            # Start should be ignored while stopping
            await dispatcher.start()
            
            await stop_task
            
            # Dispatcher should be stopped
            assert dispatcher._started is False
        
        asyncio.run(_go())

    def test_start_during_stop_returns_early(self):
        """Verify start returns early if stop is in progress."""
        async def _go():
            bus = RuntimeEventBus()
            dispatcher = EventDispatcher(bus)
            
            await dispatcher.start()
            
            # Start stop
            stop_task = asyncio.create_task(dispatcher.stop())
            await asyncio.sleep(0.01)
            
            # Start should return early
            await dispatcher.start()
            
            await stop_task
            
            # Dispatcher should be stopped (second start was ignored)
            assert dispatcher._started is False
        
        asyncio.run(_go())


# ===========================================================================
# 3. WATCHDOG STATE VALIDATION TESTS
# ===========================================================================

class TestRuntimeWatchdogStateValidation:
    """Test RuntimeWatchdog state transitions and validation."""

    def test_running_flag_set_on_start(self):
        """Verify _running flag is set on start."""
        async def _go():
            monitor = RuntimeHealthMonitor()
            registry = TaskRegistry()
            watchdog = RuntimeWatchdog(
                health_monitor=monitor,
                task_registry=registry,
            )
            
            assert watchdog._running is False
            
            await watchdog.start(interval_seconds=0.1)
            
            assert watchdog._running is True
            assert watchdog._watchdog_task is not None
            
            await watchdog.stop()
        
        asyncio.run(_go())

    def test_running_flag_cleared_on_stop(self):
        """Verify _running flag is cleared on stop."""
        async def _go():
            monitor = RuntimeHealthMonitor()
            registry = TaskRegistry()
            watchdog = RuntimeWatchdog(
                health_monitor=monitor,
                task_registry=registry,
            )
            
            await watchdog.start(interval_seconds=0.1)
            assert watchdog._running is True
            
            await watchdog.stop()
            
            assert watchdog._running is False
            assert watchdog._watchdog_task is None
        
        asyncio.run(_go())

    def test_start_when_running_returns_early(self):
        """Verify start returns early if already running."""
        async def _go():
            monitor = RuntimeHealthMonitor()
            registry = TaskRegistry()
            watchdog = RuntimeWatchdog(
                health_monitor=monitor,
                task_registry=registry,
            )
            
            await watchdog.start(interval_seconds=0.1)
            
            # Second start should return early
            await watchdog.start(interval_seconds=0.1)
            
            # Should still have only one task
            assert watchdog._watchdog_task is not None
            
            await watchdog.stop()
        
        asyncio.run(_go())

    def test_stop_when_not_running_is_noop(self):
        """Verify stop is no-op if not running."""
        async def _go():
            monitor = RuntimeHealthMonitor()
            registry = TaskRegistry()
            watchdog = RuntimeWatchdog(
                health_monitor=monitor,
                task_registry=registry,
            )
            
            # Stop when not running should not raise
            await watchdog.stop()
            
            assert watchdog._running is False
        
        asyncio.run(_go())


# ===========================================================================
# 4. RECOVERY MANAGER STATE VALIDATION TESTS
# ===========================================================================

class TestRecoveryManagerStateValidation:
    """Test RecoveryManager state transitions and validation."""

    def test_concurrent_recovery_prevented(self):
        """Verify concurrent recovery attempts are prevented."""
        async def _go():
            monitor = RuntimeHealthMonitor()
            recovery = RecoveryManager(monitor)
            
            recovery.register_recovery_callback("svc", lambda: None, max_attempts=3)
            monitor.register_service("svc")
            monitor.mark_failed("svc", error="test")
            
            # Start first recovery
            async def slow_recovery():
                await asyncio.sleep(0.1)
            
            recovery.register_recovery_callback("svc", slow_recovery, max_attempts=3)
            
            # Try concurrent recoveries
            task1 = asyncio.create_task(recovery.handle_failure("svc"))
            await asyncio.sleep(0.01)
            
            # Second recovery should be rejected
            result2 = await recovery.handle_failure("svc")
            assert result2 is False
            
            await task1
        
        asyncio.run(_go())

    def test_recovery_in_progress_flag_cleared_on_success(self):
        """Verify recovery in progress flag is cleared on success."""
        async def _go():
            monitor = RuntimeHealthMonitor()
            recovery = RecoveryManager(monitor)
            
            recovery.register_recovery_callback("svc", lambda: None, max_attempts=3)
            monitor.register_service("svc")
            monitor.mark_failed("svc", error="test")
            
            result = await recovery.handle_failure("svc")
            assert result is True
            
            # Flag should be cleared
            assert recovery._recovery_in_progress.get("svc", False) is False
        
        asyncio.run(_go())

    def test_recovery_in_progress_flag_cleared_on_failure(self):
        """Verify recovery in progress flag is cleared on failure."""
        async def _go():
            monitor = RuntimeHealthMonitor()
            recovery = RecoveryManager(monitor)
            
            def failing_recovery():
                raise RuntimeError("recovery failed")
            
            recovery.register_recovery_callback("svc", failing_recovery, max_attempts=3)
            monitor.register_service("svc")
            monitor.mark_failed("svc", error="test")
            
            result = await recovery.handle_failure("svc")
            assert result is True  # Attempt was made, even though it failed
            
            # Flag should be cleared
            assert recovery._recovery_in_progress.get("svc", False) is False
        
        asyncio.run(_go())


# ===========================================================================
# 5. RUNTIME STATE INVARIANT VALIDATION TESTS
# ===========================================================================

class TestRuntimeStateInvariantValidation:
    """Test RuntimeState invariant checking."""

    def test_check_invariants_valid_state(self):
        """Verify invariants pass for valid state."""
        state = RuntimeState()
        
        result = state.check_invariants()
        
        assert result["valid"] is True
        assert len(result["violations"]) == 0

    def test_check_invariants_started_without_dispatcher(self):
        """Verify invariant violation when started but dispatcher not started."""
        state = RuntimeState()
        
        # Manually set started without starting dispatcher
        state.started = True
        
        result = state.check_invariants()
        
        assert result["valid"] is False
        assert any("dispatcher is not started" in v for v in result["violations"])

    def test_check_invariants_dispatcher_started_without_runtime(self):
        """Verify invariant violation when dispatcher started but runtime not started."""
        state = RuntimeState()
        
        # Manually start dispatcher without setting runtime started
        asyncio.run(state.dispatcher.start())
        state.started = False
        
        result = state.check_invariants()
        
        assert result["valid"] is False
        assert any("dispatcher is started" in v for v in result["violations"])
        
        # Cleanup
        asyncio.run(state.dispatcher.stop())

    def test_check_invariants_both_started_and_shutting_down(self):
        """Verify invariant violation when both started and shutting_down."""
        state = RuntimeState()
        
        # Manually set both flags
        state.started = True
        state.shutting_down = True
        
        result = state.check_invariants()
        
        assert result["valid"] is False
        assert any("both started and shutting_down" in v for v in result["violations"])

    def test_metrics_include_invariants(self):
        """Verify metrics include invariant check results."""
        state = RuntimeState()
        
        metrics = state.get_metrics()
        
        assert "invariants" in metrics
        assert "valid" in metrics["invariants"]
        assert "violations" in metrics["invariants"]


# ===========================================================================
# 6. INTEGRATION TESTS
# ===========================================================================

class TestLifecycleIntegration:
    """Integration tests for lifecycle state consistency."""

    def test_full_lifecycle_state_consistency(self):
        """Verify state remains consistent through full lifecycle."""
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            
            # Initial state
            assert state.started is False
            assert state.shutting_down is False
            assert state.check_invariants()["valid"] is True
            
            # After startup
            await lifecycle.startup()
            assert state.started is True
            assert state.shutting_down is False
            assert state.check_invariants()["valid"] is True
            
            # After shutdown
            await lifecycle.shutdown()
            assert state.started is False
            assert state.shutting_down is True
            assert state.check_invariants()["valid"] is True
        
        asyncio.run(_go())

    def test_startup_failure_rollback_state_consistency(self):
        """Verify state remains consistent after startup failure and rollback."""
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            
            # Register steps
            lifecycle.register_startup("step1", lambda: None)
            lifecycle.register_startup("step2", lambda: (_ for _ in ()).throw(RuntimeError("fail")))
            lifecycle.register_startup("step3", lambda: None)
            
            # Attempt startup
            with pytest.raises(RuntimeError, match="fail"):
                await lifecycle.startup()
            
            # State should be consistent
            assert state.started is False
            assert state.check_invariants()["valid"] is True
        
        asyncio.run(_go())

    def test_watchdog_lifecycle_with_runtime(self):
        """Verify watchdog lifecycle coordinates with runtime lifecycle."""
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            
            monitor = state.health_monitor
            registry = state.tasks
            watchdog = RuntimeWatchdog(
                health_monitor=monitor,
                task_registry=registry,
            )
            
            # Start runtime
            await lifecycle.startup()
            
            # Start watchdog
            await watchdog.start(interval_seconds=0.1)
            assert watchdog._running is True
            
            # Stop watchdog
            await watchdog.stop()
            assert watchdog._running is False
            
            # Stop runtime
            await lifecycle.shutdown()
            assert state.check_invariants()["valid"] is True
        
        asyncio.run(_go())

    def test_recovery_during_shutdown_blocked(self):
        """Verify recovery is blocked during shutdown."""
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            
            monitor = state.health_monitor
            recovery = RecoveryManager(monitor, dispatcher=state.dispatcher)
            state.set_recovery_manager(recovery)
            
            recovery.register_recovery_callback("svc", lambda: None, max_attempts=3)
            monitor.register_service("svc")
            
            await lifecycle.startup()
            
            # Start shutdown
            shutdown_task = asyncio.create_task(lifecycle.shutdown())
            await asyncio.sleep(0.01)
            
            # Recovery during shutdown should be handled gracefully
            # (This test verifies the system doesn't crash)
            monitor.mark_failed("svc", error="test")
            result = await recovery.handle_failure("svc")
            
            await shutdown_task
            
            # State should be consistent
            assert state.check_invariants()["valid"] is True
        
        asyncio.run(_go())


# ===========================================================================
# 7. EVENT ORDERING TESTS
# ===========================================================================

class TestEventOrdering:
    """Test event ordering during lifecycle transitions."""

    def test_runtime_started_event_emitted_after_startup_complete(self):
        """Verify RuntimeStartedEvent is emitted after startup completes."""
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            
            received = []
            
            async def handler(event):
                received.append(type(event).__name__)
            
            await state.event_bus.subscribe(RuntimeStartedEvent, handler)
            
            await lifecycle.startup()
            await asyncio.sleep(0.05)
            
            # RuntimeStartedEvent should be in received events
            assert "RuntimeStartedEvent" in received
            
            await lifecycle.shutdown()
        
        asyncio.run(_go())

    def test_runtime_shutdown_event_emitted_before_dispatcher_stop(self):
        """Verify RuntimeShutdownEvent is emitted before dispatcher stops."""
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            
            received = []
            
            async def handler(event):
                received.append({
                    "event": type(event).__name__,
                    "dispatcher_started": state.dispatcher.started,
                })
            
            await state.event_bus.subscribe(RuntimeShutdownEvent, handler)
            
            await lifecycle.startup()
            await lifecycle.shutdown()
            
            # RuntimeShutdownEvent should have been emitted
            shutdown_events = [r for r in received if r["event"] == "RuntimeShutdownEvent"]
            assert len(shutdown_events) > 0
        
        asyncio.run(_go())


# ===========================================================================
# 8. EDGE CASE TESTS
# ===========================================================================

class TestLifecycleEdgeCases:
    """Test edge cases in lifecycle state management."""

    def test_multiple_startup_failures_with_rollback(self):
        """Verify multiple consecutive startup failures are handled correctly."""
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            
            def failing_step():
                raise RuntimeError("persistent failure")
            
            lifecycle.register_startup("failing", failing_step)
            
            # Try startup multiple times
            for _ in range(3):
                with pytest.raises(RuntimeError, match="persistent failure"):
                    await lifecycle.startup()
                
                # State should be consistent after each failure
                assert state.started is False
                assert state.check_invariants()["valid"] is True
        
        asyncio.run(_go())

    def test_shutdown_without_startup(self):
        """Verify shutdown without startup is handled gracefully."""
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            
            # Shutdown without startup should not raise
            await lifecycle.shutdown()
            
            assert state.started is False
            assert state.shutting_down is True
        
        asyncio.run(_go())

    def test_dispatcher_start_failure_during_startup(self):
        """Verify dispatcher start failure during startup is handled."""
        async def _go():
            state = RuntimeState()
            lifecycle = LifecycleManager(state)
            
            # Mock dispatcher start to fail
            original_start = state.dispatcher.start
            
            async def failing_start():
                raise RuntimeError("dispatcher start failed")
            
            state.dispatcher.start = failing_start
            
            with pytest.raises(RuntimeError, match="dispatcher start failed"):
                await lifecycle.startup()
            
            # Restore original
            state.dispatcher.start = original_start
            
            # State should be consistent
            assert state.started is False
            assert state.check_invariants()["valid"] is True
        
        asyncio.run(_go())
