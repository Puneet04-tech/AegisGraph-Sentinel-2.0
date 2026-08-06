"""Unit tests for the circuit breaker utility"""

import threading

import pytest

from src.utils.circuit_breaker import CircuitBreaker, CircuitOpenError


class _FakeClock:
    def __init__(self, now=0.0):
        self._now = now

    def __call__(self):
        return self._now

    def advance(self, seconds):
        self._now += seconds


def _boom():
    raise RuntimeError("boom")


class TestCircuitBreakerClosedState:
    def test_stays_closed_on_successful_calls(self):
        cb = CircuitBreaker()
        for _ in range(50):
            assert cb.call(lambda: 42) == 42
        assert cb.state == CircuitBreaker.CLOSED
        assert cb.current_failures() == 0

    def test_original_exception_propagates_while_closed(self):
        cb = CircuitBreaker()
        with pytest.raises(RuntimeError, match="boom"):
            cb.call(_boom)
        assert cb.state == CircuitBreaker.CLOSED
        assert cb.current_failures() == 1


class TestCircuitBreakerOpenState:
    def test_opens_after_failure_threshold_consecutive_failures(self):
        clock = _FakeClock()
        cb = CircuitBreaker(failure_threshold=3, reset_timeout=30.0, clock=clock)
        for _ in range(3):
            with pytest.raises(RuntimeError):
                cb.call(_boom)
        assert cb.state == CircuitBreaker.OPEN
        assert cb.current_failures() == 3

    def test_subsequent_calls_raise_circuit_open_error(self):
        clock = _FakeClock()
        cb = CircuitBreaker(failure_threshold=2, reset_timeout=30.0, clock=clock)
        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(_boom)
        with pytest.raises(CircuitOpenError):
            cb.call(_boom)
        assert cb.state == CircuitBreaker.OPEN

    def test_no_trial_before_reset_timeout_elapses(self):
        clock = _FakeClock()
        cb = CircuitBreaker(failure_threshold=1, reset_timeout=10.0, clock=clock)
        with pytest.raises(RuntimeError):
            cb.call(_boom)
        clock.advance(9.0)
        with pytest.raises(CircuitOpenError):
            cb.call(_boom)
        assert cb.state == CircuitBreaker.OPEN


class TestCircuitBreakerHalfOpenState:
    def test_trial_allowed_after_reset_timeout_and_success_recloses(self):
        clock = _FakeClock()
        cb = CircuitBreaker(failure_threshold=2, reset_timeout=10.0, clock=clock)
        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(_boom)
        assert cb.state == CircuitBreaker.OPEN

        clock.advance(10.0)
        assert cb.call(lambda: "recovered") == "recovered"
        assert cb.state == CircuitBreaker.CLOSED
        assert cb.current_failures() == 0

    def test_trial_failure_reopens_circuit(self):
        clock = _FakeClock()
        cb = CircuitBreaker(failure_threshold=2, reset_timeout=10.0, clock=clock)
        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(_boom)
        assert cb.state == CircuitBreaker.OPEN

        clock.advance(10.0)
        with pytest.raises(RuntimeError):
            cb.call(_boom)
        assert cb.state == CircuitBreaker.OPEN
        with pytest.raises(CircuitOpenError):
            cb.call(_boom)

    def test_recovery_attempts_limit_half_open_trials(self):
        clock = _FakeClock()
        cb = CircuitBreaker(
            failure_threshold=1,
            reset_timeout=10.0,
            clock=clock,
            recovery_attempts=2,
        )
        with pytest.raises(RuntimeError):
            cb.call(_boom)
        clock.advance(10.0)

        entered = 0
        entered_cv = threading.Condition()
        release = threading.Event()
        trials = []

        def slow():
            nonlocal entered
            with entered_cv:
                entered += 1
                if entered == 2:
                    entered_cv.notify_all()
            release.wait(5)
            return "ok"

        def run_trial():
            try:
                trials.append(cb.call(slow))
            except CircuitOpenError:
                trials.append(CircuitOpenError)

        threads = [threading.Thread(target=run_trial) for _ in range(2)]
        for t in threads:
            t.start()

        with entered_cv:
            assert entered_cv.wait_for(lambda: entered == 2, timeout=5)
        assert cb.state == CircuitBreaker.HALF_OPEN

        with pytest.raises(CircuitOpenError):
            cb.call(slow)

        release.set()
        for t in threads:
            t.join()
        assert trials == ["ok", "ok"]
        assert cb.state == CircuitBreaker.CLOSED
        assert cb.current_failures() == 0


class TestCircuitBreakerStateMachine:
    def test_state_transitions_closed_to_open_to_half_open_to_closed(self):
        clock = _FakeClock()
        cb = CircuitBreaker(failure_threshold=2, reset_timeout=5.0, clock=clock)
        assert cb.state == CircuitBreaker.CLOSED

        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(_boom)
        assert cb.state == CircuitBreaker.OPEN

        clock.advance(5.0)
        entered = threading.Event()
        release = threading.Event()

        def slow():
            entered.set()
            release.wait(5)
            return "recovered"

        t = threading.Thread(target=lambda: cb.call(slow))
        t.start()
        assert entered.wait(5)
        assert cb.state == CircuitBreaker.HALF_OPEN

        release.set()
        t.join()
        assert cb.state == CircuitBreaker.CLOSED
        assert cb.current_failures() == 0

    def test_reset_returns_to_closed_and_clears_failures(self):
        clock = _FakeClock()
        cb = CircuitBreaker(failure_threshold=2, reset_timeout=30.0, clock=clock)
        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(_boom)
        assert cb.state == CircuitBreaker.OPEN
        assert cb.current_failures() == 2

        cb.reset()
        assert cb.state == CircuitBreaker.CLOSED
        assert cb.current_failures() == 0
        assert cb.call(lambda: 7) == 7


class TestCircuitBreakerThreadSafety:
    def test_concurrent_calls_leave_consistent_state(self):
        cb = CircuitBreaker(failure_threshold=10, reset_timeout=30.0)
        failures = []
        rejections = []

        def worker():
            for _ in range(200):
                try:
                    cb.call(_boom)
                except CircuitOpenError:
                    rejections.append(1)
                    break
                except RuntimeError:
                    failures.append(1)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert cb.state == CircuitBreaker.OPEN
        assert cb.current_failures() == cb.failure_threshold
        assert len(failures) >= cb.failure_threshold
        assert rejections


class TestCircuitBreakerValidation:
    def test_constructor_rejects_invalid_parameters(self):
        with pytest.raises(ValueError):
            CircuitBreaker(failure_threshold=0)
        with pytest.raises(ValueError):
            CircuitBreaker(reset_timeout=0)
        with pytest.raises(ValueError):
            CircuitBreaker(recovery_attempts=0)
