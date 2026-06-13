# Runtime Lifecycle State Transition Audit Report

## Executive Summary

This document provides a comprehensive audit of runtime lifecycle state transitions across the AegisGraph Sentinel 2.0 platform. The audit identifies state inconsistencies, missing validation, and potential race conditions in startup, shutdown, rollback, and recovery paths.

**Audit Date:** 2026-06-10  
**Scope:** LifecycleManager, RecoveryManager, RuntimeWatchdog, EventDispatcher, RuntimeState  
**Severity:** High - State inconsistencies can lead to undefined behavior during failures

---

## Phase 1: Component Analysis

### 1.1 LifecycleManager

**Location:** `src/runtime/lifecycle_manager.py`

**State Flags:**
- `_started` (private bool)
- `_shutting_down` (private bool)
- `runtime_state.started` (public bool)
- `runtime_state.shutting_down` (public bool)

**Startup Flow:**
```
idle → starting → started
```
1. Acquire lock
2. Check if already started (idempotent)
3. Set `runtime_state.shutting_down = False`
4. Register default event subscriptions
5. Start dispatcher if not started
6. Execute startup steps sequentially
7. On success: set `_started = True`, `runtime_state.started = True`, emit RuntimeStartedEvent
8. On failure: rollback completed steps

**Shutdown Flow:**
```
started → shutting_down → stopped
```
1. Acquire lock
2. Check if already shutting down (idempotent)
3. Set `_shutting_down = True`, `runtime_state.shutting_down = True`
4. Execute shutdown steps in reverse order
5. Set `_started = False`, `runtime_state.started = False`
6. Emit RuntimeShutdownEvent
7. Stop dispatcher

**Rollback Flow:**
```
starting → rolling_back → stopped
```
1. Execute completed startup steps in reverse as shutdown steps
2. Stop dispatcher if started
3. Set `runtime_state.started = False`, `_started = False`

**Issues Identified:**
1. **No dispatcher state validation**: Sets `runtime_state.started = True` before confirming dispatcher is actually started
2. **Incomplete rollback state**: Sets `runtime_state.started = False` in rollback but doesn't validate dispatcher stopped successfully
3. **No invariant checking**: No validation that state transitions are valid (e.g., can't shutdown if not started)
4. **Missing coordination**: No check that `runtime_state.shutting_down` is False before allowing startup

### 1.2 EventDispatcher

**Location:** `src/runtime/events/dispatcher.py`

**State Flags:**
- `_started` (bool)
- `_running` (bool)
- `_stop_requested` (asyncio.Event)
- `_task` (optional asyncio.Task)

**Start Flow:**
```
stopped → starting → running
```
1. Check if already started (idempotent)
2. Set `_started = True`
3. Reset queue and event
4. Set `_running = True`
5. Clear `_stop_requested`
6. Create processing task

**Stop Flow:**
```
running → stopping → stopped
```
1. Check if started
2. Set `_started = False` ⚠️ **ISSUE**: Set before stop completes
3. Set `_running = False`
4. Set `_stop_requested`
5. Await task completion
6. Clear overflow

**Issues Identified:**
1. **State flag divergence**: `_started` is set to False before `stop()` completes, creating a window where `_started=False` but task is still running
2. **No guard against concurrent start/stop**: Can call `start()` while `stop()` is in progress
3. **No validation of task state**: Doesn't verify task is actually done before clearing flags
4. **Cross-event-loop handling**: Has special handling for cross-event-loop errors but no state validation

### 1.3 RuntimeWatchdog

**Location:** `src/runtime/watchdog.py`

**State Flags:**
- `_watchdog_task` (optional asyncio.Task)

**Start Flow:**
```
idle → running
```
1. Check if task exists and not done (idempotent)
2. Create background task for periodic health validation

**Stop Flow:**
```
running → idle
```
1. Check if task exists and not done
2. Cancel task
3. Await task completion
4. Set task to None

**Issues Identified:**
1. **No explicit state flag**: Relies on `_watchdog_task` being None/done instead of explicit state
2. **No state validation**: No check that watchdog is not already running before start
3. **No coordination with lifecycle**: Can start watchdog during shutdown
4. **No recovery state tracking**: Doesn't track if recovery is in progress

### 1.4 RecoveryManager

**Location:** `src/runtime/recovery_manager.py`

**State Flags:**
- **None** - No explicit state tracking

**Recovery Flow:**
```
failure_detected → recovery_attempted → success|failure
```
1. Check if callback registered
2. Get health snapshot
3. Check max attempts
4. Check policy engine
5. Check resource manager
6. Increment restart attempts
7. Emit RecoveryTriggeredEvent
8. Execute recovery callback

**Issues Identified:**
1. **No state tracking**: No explicit state to track recovery in progress
2. **No lifecycle coordination**: Can attempt recovery during shutdown
3. **No concurrent recovery guard**: Multiple recovery attempts can happen simultaneously
4. **No rollback state**: Doesn't track if rollback is in progress

### 1.5 RuntimeState

**Location:** `src/runtime/runtime_state.py`

**State Flags:**
- `started` (bool)
- `shutting_down` (bool)

**Issues Identified:**
1. **No validation**: Flags can be set arbitrarily without validation
2. **No invariant checking**: No checks that state combinations are valid
3. **No coordination**: No synchronization with component states
4. **External mutation**: Flags are set externally by LifecycleManager without guards

---

## Phase 2: State Invariant Analysis

### 2.1 Critical Invariants

The following invariants should hold true at all times:

1. **Startup Completion Invariant**
   - `runtime_state.started == True` ⇒ All startup steps completed successfully
   - `runtime_state.started == True` ⇒ Dispatcher is started and running
   - `runtime_state.started == True` ⇒ `runtime_state.shutting_down == False`

2. **Shutdown Invariant**
   - `runtime_state.shutting_down == True` ⇒ No new startup steps can begin
   - `runtime_state.shutting_down == True` ⇒ Dispatcher stop has been initiated
   - `runtime_state.started == False` ⇒ All shutdown steps completed

3. **Dispatcher State Invariant**
   - `dispatcher._started == True` ⇒ `dispatcher._running == True`
   - `dispatcher._started == False` ⇒ `dispatcher._running == False` (after stop completes)
   - `dispatcher._started == True` ⇒ Processing task is running

4. **Lifecycle State Invariant**
   - `lifecycle._started == True` ⇔ `runtime_state.started == True`
   - `lifecycle._shutting_down == True` ⇔ `runtime_state.shutting_down == True`

5. **Watchdog State Invariant**
   - `watchdog._watchdog_task is not None` ⇒ Watchdog is running
   - `watchdog._watchdog_task is None` ⇒ Watchdog is stopped

### 2.2 Invariant Violations Found

| Invariant | Violation Location | Severity |
|-----------|-------------------|----------|
| Startup Completion | LifecycleManager.startup() line 92 | High |
| Dispatcher State | EventDispatcher.stop() line 93 | High |
| Lifecycle State | LifecycleManager._rollback_startup() line 171 | Medium |
| Watchdog State | RuntimeWatchdog.start() line 52 | Medium |

---

## Phase 3: Failure Paths Analysis

### 3.1 Startup Failure Paths

**Path 1: Early Startup Step Failure**
```
startup() → step1 succeeds → step2 fails → rollback(step1) → dispatcher.stop() → state=stopped
```
- **Current behavior**: Sets `runtime_state.started = False` in rollback
- **Issue**: Doesn't validate dispatcher stopped successfully
- **Risk**: Dispatcher may still be running after rollback

**Path 2: Dispatcher Start Failure**
```
startup() → dispatcher.start() fails → exception propagates → state inconsistent
```
- **Current behavior**: Exception propagates, no rollback
- **Issue**: `runtime_state.shutting_down` was set to False but startup didn't complete
- **Risk**: State indicates not shutting down but startup failed

**Path 3: Event Subscription Failure**
```
startup() → register_default_subscriptions() fails → exception propagates
```
- **Current behavior**: Exception propagates
- **Issue**: No cleanup of partial state
- **Risk**: Partial event subscriptions remain

### 3.2 Shutdown Failure Paths

**Path 1: Shutdown Step Failure**
```
shutdown() → step1 succeeds → step2 fails → remaining steps not executed
```
- **Current behavior**: Exception propagates, state remains inconsistent
- **Issue**: `runtime_state.started = False` set but not all shutdown steps ran
- **Risk**: Resources not cleaned up

**Path 2: Dispatcher Stop Failure**
```
shutdown() → steps complete → dispatcher.stop() fails → exception swallowed or propagates
```
- **Current behavior**: Depends on exception type
- **Issue**: Dispatcher may not stop cleanly
- **Risk**: Events may continue processing after shutdown

### 3.3 Rollback Failure Paths

**Path 1: Rollback Step Failure**
```
rollback() → step1 rollback succeeds → step2 rollback fails → continues with remaining
```
- **Current behavior**: Logs error, continues
- **Issue**: Some resources not cleaned up
- **Risk**: Partial cleanup leaves system in inconsistent state

**Path 2: Dispatcher Stop During Rollback Failure**
```
rollback() → steps complete → dispatcher.stop() fails → logs error
```
- **Current behavior**: Logs error, continues
- **Issue**: Dispatcher may still be running
- **Risk**: Events may continue processing after rollback

### 3.4 Recovery Failure Paths

**Path 1: Recovery During Shutdown**
```
shutdown() → recovery triggered → recovery attempts to start services
```
- **Current behavior**: Recovery proceeds without checking shutdown state
- **Issue**: Can start services during shutdown
- **Risk**: Resources not cleaned up properly

**Path 2: Concurrent Recovery Attempts**
```
failure → recovery1 starts → recovery2 starts before recovery1 completes
```
- **Current behavior**: Both proceed concurrently
- **Issue**: No coordination between recovery attempts
- **Risk**: Resource conflicts, double initialization

---

## Phase 4: Event Ordering Analysis

### 4.1 Startup Event Ordering

**Current Order:**
1. `runtime_startup_started` (log/audit)
2. `dispatcher_started` (log)
3. `runtime_startup_step_started` (for each step)
4. `runtime_startup_step_complete` (for each step)
5. `runtime_startup_complete` (log/audit)
6. `RuntimeStartedEvent` (dispatched)

**Issues:**
- `RuntimeStartedEvent` is dispatched after `runtime_startup_complete` log
- If dispatcher fails to dispatch event, it's not logged
- No event if startup fails (only failure logs)

### 4.2 Shutdown Event Ordering

**Current Order:**
1. `runtime_shutdown_started` (log/audit)
2. `runtime_shutdown_step_started` (for each step)
3. `runtime_shutdown_step_complete` (for each step)
4. `runtime_shutdown_complete` (log/audit)
5. `RuntimeShutdownEvent` (dispatched)
6. Dispatcher stop

**Issues:**
- `RuntimeShutdownEvent` is dispatched before dispatcher stops
- If dispatcher is slow, event may not be delivered before stop
- No event if shutdown fails

### 4.3 Rollback Event Ordering

**Current Order:**
1. `runtime_startup_rollback` (log)
2. `runtime_startup_step_failed` (log)
3. Rollback steps execute
4. `runtime_startup_rollback_error` (if rollback fails)
5. Dispatcher stop

**Issues:**
- No dedicated rollback event type
- No event to signal rollback completion
- Dispatcher stop failure is logged but not dispatched as event

---

## Phase 5: Recommended Fixes

### 5.1 High Priority Fixes

**Fix 1: Add dispatcher state validation in LifecycleManager**
- Verify dispatcher is actually started before setting `runtime_state.started = True`
- Add check in rollback that dispatcher stopped successfully
- Add invariant checking methods

**Fix 2: Fix EventDispatcher state flag ordering**
- Set `_started = False` only after stop completes successfully
- Add guard against concurrent start/stop operations
- Add explicit state enum instead of multiple bool flags

**Fix 3: Add explicit state to RuntimeWatchdog**
- Add `_running` bool flag
- Add state validation in start/stop
- Add coordination with lifecycle state

**Fix 4: Add state tracking to RecoveryManager**
- Add `_recovery_in_progress` flag
- Check `runtime_state.shutting_down` before attempting recovery
- Add guard against concurrent recovery attempts

**Fix 5: Add invariant validation to RuntimeState**
- Add validation methods for state transitions
- Add invariant checking that can be called at any time
- Add guards against invalid state combinations

### 5.2 Medium Priority Fixes

**Fix 6: Add rollback completion event**
- Create `RuntimeRollbackCompleteEvent`
- Dispatch after rollback completes
- Include metadata about what was rolled back

**Fix 7: Improve event ordering**
- Dispatch `RuntimeStartedEvent` before `runtime_startup_complete` log
- Ensure dispatcher can deliver event before setting state
- Add events for failure scenarios

**Fix 8: Add lifecycle state machine**
- Create explicit state enum (IDLE, STARTING, STARTED, SHUTTING_DOWN, STOPPED, ROLLING_BACK)
- Add state transition validation
- Add state transition logging

---

## Phase 6: Test Coverage Gaps

### 6.1 Missing Test Scenarios

1. **Startup Failure Scenarios**
   - Dispatcher start failure during startup
   - Event subscription failure during startup
   - Partial startup with rollback verification

2. **Shutdown Failure Scenarios**
   - Shutdown step failure
   - Dispatcher stop failure during shutdown
   - Concurrent shutdown attempts

3. **Rollback Scenarios**
   - Rollback step failure
   - Dispatcher stop failure during rollback
   - Partial rollback state verification

4. **State Transition Scenarios**
   - Startup during shutdown (should fail)
   - Shutdown during startup (should handle gracefully)
   - Recovery during shutdown (should be blocked)

5. **Concurrent Scenarios**
   - Concurrent startup attempts
   - Concurrent shutdown attempts
   - Concurrent recovery attempts

6. **Event Ordering Scenarios**
   - Verify event order in successful startup
   - Verify event order in failed startup
   - Verify event order in shutdown
   - Verify event order in rollback

---

## Conclusion

The runtime lifecycle implementation has several state consistency issues that could lead to undefined behavior during failure scenarios. The most critical issues are:

1. **Dispatcher state flag ordering** in EventDispatcher.stop()
2. **Missing dispatcher state validation** in LifecycleManager
3. **No state tracking** in RecoveryManager
4. **No invariant validation** in RuntimeState

These issues should be fixed with minimal changes to preserve backward compatibility while adding necessary state validation and guards.

**Next Steps:**
1. Implement high-priority fixes
2. Add comprehensive regression tests
3. Verify existing tests still pass
4. Update documentation

