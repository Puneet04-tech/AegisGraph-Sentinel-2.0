"""
Health probes.

``HealthMonitor.check_health`` decided whether a component was healthy with
``random.random() > 0.05`` and attached a ``random.uniform(5, 200)`` response
time. Nothing was ever contacted.

That is the worst failure mode a monitor can have, because it fails **both**
ways at once: a fully healthy platform is reported unhealthy roughly one check
in twenty, training operators to ignore the signal, while a genuinely dead
component is reported healthy 95% of the time — so the one alert that mattered
is indistinguishable from the constant background noise.

This module supplies the probes the monitor should have been calling.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Callable, Optional, Protocol, Sequence

try:
    import requests
except ImportError:  # pragma: no cover - requests is a declared dependency
    requests = None

# A health check that hangs is itself an outage, so probes fail fast.
DEFAULT_TIMEOUT_SECONDS = 5.0

# Status codes treated as healthy by an HTTP probe unless overridden.
DEFAULT_HEALTHY_STATUSES = (200, 204)


@dataclass
class ProbeResult:
    """Outcome of one probe attempt."""

    healthy: bool
    latency_ms: float
    error: Optional[str] = None
    detail: Optional[str] = None

    def __bool__(self) -> bool:
        return self.healthy


class Probe(Protocol):
    """Anything that can be asked whether a component is up."""

    def __call__(self) -> ProbeResult:  # pragma: no cover - structural type
        ...


def _measure(operation: Callable[[], "tuple[bool, Optional[str], Optional[str]]"]) -> ProbeResult:
    """Run an operation, timing it and containing any exception.

    Latency is measured with ``time.monotonic()`` rather than wall-clock time,
    so an NTP correction mid-probe cannot produce a negative or absurd
    duration.
    """
    started = time.monotonic()
    try:
        healthy, error, detail = operation()
    except Exception as exc:
        # A probe raising is a failed probe, never a crashed monitor.
        elapsed_ms = (time.monotonic() - started) * 1000.0
        return ProbeResult(
            healthy=False,
            latency_ms=elapsed_ms,
            error=f"{type(exc).__name__}: {exc}",
        )

    elapsed_ms = (time.monotonic() - started) * 1000.0
    return ProbeResult(healthy=healthy, latency_ms=elapsed_ms, error=error, detail=detail)


class HttpProbe:
    """Probe an HTTP endpoint, treating configured status codes as healthy."""

    def __init__(
        self,
        url: str,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        healthy_statuses: Sequence[int] = DEFAULT_HEALTHY_STATUSES,
        verify_tls: bool = True,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.healthy_statuses = tuple(healthy_statuses)
        self.verify_tls = verify_tls

    def __call__(self) -> ProbeResult:
        def operation():
            if requests is None:  # pragma: no cover - dependency always present
                return False, "requests is unavailable", None
            response = requests.get(
                self.url, timeout=self.timeout, verify=self.verify_tls
            )
            status = response.status_code
            if status in self.healthy_statuses:
                return True, None, f"HTTP {status}"
            return False, f"unexpected status {status}", f"HTTP {status}"

        return _measure(operation)


class TcpProbe:
    """Probe a TCP endpoint by opening and closing a connection."""

    def __init__(
        self, host: str, port: int, timeout: float = DEFAULT_TIMEOUT_SECONDS
    ) -> None:
        self.host = host
        self.port = int(port)
        self.timeout = timeout

    def __call__(self) -> ProbeResult:
        def operation():
            connection = socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            )
            connection.close()
            return True, None, f"connected to {self.host}:{self.port}"

        return _measure(operation)


class CallableProbe:
    """Probe via a supplied callable.

    The callable may return a ``ProbeResult``, a bool, or nothing at all —
    returning without raising is treated as success, so an existing
    ``ping()``-style function can be used unchanged.
    """

    def __init__(self, check: Callable[[], object]) -> None:
        self.check = check

    def __call__(self) -> ProbeResult:
        started = time.monotonic()
        try:
            outcome = self.check()
        except Exception as exc:
            return ProbeResult(
                healthy=False,
                latency_ms=(time.monotonic() - started) * 1000.0,
                error=f"{type(exc).__name__}: {exc}",
            )

        elapsed_ms = (time.monotonic() - started) * 1000.0
        if isinstance(outcome, ProbeResult):
            # Preserve the caller's own measurement if it made one.
            return outcome
        if outcome is None:
            return ProbeResult(healthy=True, latency_ms=elapsed_ms)
        return ProbeResult(
            healthy=bool(outcome),
            latency_ms=elapsed_ms,
            error=None if outcome else "probe returned a falsy result",
        )
