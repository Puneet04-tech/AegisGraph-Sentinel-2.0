"""Circuit breaker for guarding calls to unreliable dependencies.

Tracks three states: CLOSED (normal operation), OPEN (fast-fail with
``CircuitOpenError``), and HALF_OPEN (limited trial calls). A configurable
clock keeps the breaker fully testable without real sleeps.
"""

import threading
import time


class CircuitOpenError(Exception):
    """Raised when a call is rejected because the circuit is open."""


class CircuitBreaker:
    """Stateful circuit breaker protecting calls to an unreliable target."""

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

    def __init__(
        self,
        failure_threshold: int = 5,
        reset_timeout: float = 30.0,
        *,
        clock=None,
        recovery_attempts: int = 1,
    ) -> None:
        if failure_threshold <= 0:
            raise ValueError("failure_threshold must be positive")
        if reset_timeout <= 0:
            raise ValueError("reset_timeout must be positive")
        if recovery_attempts <= 0:
            raise ValueError("recovery_attempts must be positive")
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.recovery_attempts = recovery_attempts
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()
        self._state = self.CLOSED
        self._failures = 0
        self._opened_at: float | None = None
        self._trials_used = 0

    @property
    def state(self) -> str:
        return self._state

    def current_failures(self) -> int:
        with self._lock:
            return self._failures

    def reset(self) -> None:
        with self._lock:
            self._state = self.CLOSED
            self._failures = 0
            self._trials_used = 0
            self._opened_at = None

    def call(self, fn, *args, **kwargs):
        """Execute ``fn`` guarded by the current circuit state."""
        with self._lock:
            now = self._clock()
            if self._state == self.OPEN and now - self._opened_at >= self.reset_timeout:
                self._state = self.HALF_OPEN
                self._trials_used = 0
            if self._state == self.OPEN:
                raise CircuitOpenError(
                    f"circuit is open; {self._clock() - self._opened_at:.1f}s "
                    f"of {self.reset_timeout}s timeout elapsed"
                )
            if self._state == self.HALF_OPEN:
                if self._trials_used >= self.recovery_attempts:
                    raise CircuitOpenError("trial calls exhausted in half-open state")
                self._trials_used += 1

        try:
            result = fn(*args, **kwargs)
        except Exception:
            with self._lock:
                if self._state == self.CLOSED:
                    self._failures += 1
                    if self._failures >= self.failure_threshold:
                        self._state = self.OPEN
                        self._opened_at = self._clock()
                elif self._state == self.HALF_OPEN:
                    self._state = self.OPEN
                    self._opened_at = self._clock()
            raise
        else:
            with self._lock:
                if self._state == self.HALF_OPEN:
                    self._state = self.CLOSED
                    self._failures = 0
                    self._trials_used = 0
                elif self._state == self.CLOSED:
                    self._failures = 0
            return result
