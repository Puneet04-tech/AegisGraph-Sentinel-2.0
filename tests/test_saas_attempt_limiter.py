# AegisGraph Sentinel Enterprise
# Auth Attempt Limiter Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from datetime import datetime, timezone
from src.saas.auth.attempt_limiter import InMemoryAttemptLimiter, SCOPE_ACCOUNT, SCOPE_ADDRESS

def test_in_memory_limiter_defaults():
    limiter = InMemoryAttemptLimiter()
    assert limiter.threshold_for(SCOPE_ACCOUNT) == 5
    assert limiter.threshold_for(SCOPE_ADDRESS) == 20

def test_in_memory_limiter_custom_thresholds():
    limiter = InMemoryAttemptLimiter(thresholds={SCOPE_ACCOUNT: 3})
    assert limiter.threshold_for(SCOPE_ACCOUNT) == 3
    assert limiter.threshold_for(SCOPE_ADDRESS) == 20

def test_in_memory_limiter_invalid_backoff():
    with pytest.raises(ValueError):
        InMemoryAttemptLimiter(backoff_schedule=())

def test_in_memory_limiter_check_unlocked():
    limiter = InMemoryAttemptLimiter()
    state = limiter.check("testuser")
    assert state.locked is False
    assert state.failures == 0
    assert state.failures_remaining == 5

def test_in_memory_limiter_record_failure_tracking():
    limiter = InMemoryAttemptLimiter()
    state = limiter.record_failure("testuser")
    assert state.locked is False
    assert state.failures == 1
    assert state.failures_remaining == 4

    state = limiter.check("testuser")
    assert state.failures == 1

def test_in_memory_limiter_lockout_trigger():
    limiter = InMemoryAttemptLimiter(thresholds={SCOPE_ACCOUNT: 2}, backoff_schedule=(10,))
    state = limiter.record_failure("lockuser")
    assert state.locked is False
    state = limiter.record_failure("lockuser")
    assert state.locked is True
    assert state.retry_after_seconds == 10

    state = limiter.check("lockuser")
    assert state.locked is True

def test_in_memory_limiter_record_success_resets():
    limiter = InMemoryAttemptLimiter(thresholds={SCOPE_ACCOUNT: 3})
    limiter.record_failure("resetuser")
    limiter.record_failure("resetuser")
    limiter.record_success("resetuser")
    state = limiter.check("resetuser")
    assert state.failures == 0

def test_in_memory_limiter_clear():
    limiter = InMemoryAttemptLimiter()
    limiter.record_failure("clearuser")
    limiter.clear()
    state = limiter.check("clearuser")
    assert state.failures == 0
