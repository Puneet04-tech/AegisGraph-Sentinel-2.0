"""Health checks must probe something.

`HealthMonitor.check_health` decided whether a component was healthy with
`random.random() > 0.05` and attached a `random.uniform(5, 200)` response time.
Nothing was ever contacted.

That fails both ways at once: a healthy platform is reported unhealthy roughly
one check in twenty, training operators to ignore the signal, while a dead
component is reported healthy 95% of the time. These tests pin both directions.
"""

from __future__ import annotations

import time

import pytest

from src.observability.health_monitor import HealthMonitor
from src.observability.models import ComponentStatus
from src.observability.probes import (
    CallableProbe,
    HttpProbe,
    ProbeResult,
    TcpProbe,
)
from src.observability.store import ObservabilityStore


@pytest.fixture
def monitor() -> HealthMonitor:
    return HealthMonitor(store=ObservabilityStore())


def register(monitor, name, kind="service", probe=None, metadata=None):
    """Register a component and return the store-generated component_id."""
    health = monitor.register_component(
        name, kind, metadata=metadata, probe=probe
    )
    return health.component_id


def always_up() -> ProbeResult:
    return ProbeResult(healthy=True, latency_ms=12.5)


def always_down() -> ProbeResult:
    return ProbeResult(healthy=False, latency_ms=8.0, error="connection refused")


class TestDeterminism:
    """The defect this PR exists for."""

    def test_a_dead_component_is_reported_unhealthy_every_single_time(self, monitor):
        api_id = register(monitor, "api", "service", probe=always_down)

        statuses = {
            monitor.check_health(api_id)["status"] for _ in range(200)
        }
        assert ComponentStatus.HEALTHY.value not in statuses, (
            "a dead component reported healthy: the check is still a coin flip"
        )

    def test_a_live_component_is_reported_healthy_every_single_time(self, monitor):
        api_id = register(monitor, "api", "service", probe=always_up)

        statuses = {
            monitor.check_health(api_id)["status"] for _ in range(200)
        }
        assert statuses == {ComponentStatus.HEALTHY.value}

    def test_the_module_no_longer_imports_random(self):
        import src.observability.health_monitor as module

        assert not hasattr(module, "random"), "health_monitor still imports random"


class TestLatencyIsMeasured:
    def test_latency_reflects_a_slow_probe(self, monitor):
        def slow() -> ProbeResult:
            time.sleep(0.05)
            return ProbeResult(healthy=True, latency_ms=0.0)

        slow_id = register(monitor, "slow", probe=CallableProbe(slow))
        result = monitor.check_health(slow_id)

        # CallableProbe measures for itself when the callable does not.
        assert result["response_time_ms"] >= 0.0

    def test_callable_probe_measures_its_own_latency(self):
        def slow():
            time.sleep(0.05)

        result = CallableProbe(slow)()
        assert result.healthy is True
        assert result.latency_ms >= 45.0

    def test_latency_is_never_negative(self):
        result = CallableProbe(lambda: True)()
        assert result.latency_ms >= 0.0


class TestFailureThreshold:
    def test_one_failure_degrades_rather_than_flapping_to_unhealthy(self, monitor):
        api_id = register(monitor, "api", "service", probe=always_up)
        monitor.check_health(api_id)

        monitor.set_probe(api_id, always_down)
        assert monitor.check_health(api_id)["status"] == ComponentStatus.DEGRADED.value

    def test_repeated_failures_reach_unhealthy(self, monitor):
        api_id = register(monitor, "api", "service", probe=always_down)

        monitor.check_health(api_id)
        assert monitor.check_health(api_id)["status"] == ComponentStatus.UNHEALTHY.value

    def test_a_configurable_threshold_is_honoured(self):
        monitor = HealthMonitor(store=ObservabilityStore(), failure_threshold=4)
        api_id = register(monitor, "api", "service", probe=always_down)

        for _ in range(3):
            assert monitor.check_health(api_id)["status"] == ComponentStatus.DEGRADED.value
        assert monitor.check_health(api_id)["status"] == ComponentStatus.UNHEALTHY.value

    def test_recovery_resets_the_failure_count(self, monitor):
        api_id = register(monitor, "api", "service", probe=always_down)
        monitor.check_health(api_id)
        monitor.check_health(api_id)

        monitor.set_probe(api_id, always_up)
        recovered = monitor.check_health(api_id)
        assert recovered["status"] == ComponentStatus.HEALTHY.value
        assert recovered["consecutive_failures"] == 0

        # And a subsequent single failure degrades rather than going straight
        # back to unhealthy.
        monitor.set_probe(api_id, always_down)
        assert monitor.check_health(api_id)["status"] == ComponentStatus.DEGRADED.value

    def test_consecutive_failures_are_reported(self, monitor):
        api_id = register(monitor, "api", "service", probe=always_down)
        counts = [monitor.check_health(api_id)["consecutive_failures"] for _ in range(3)]
        assert counts == [1, 2, 3]

    def test_a_zero_threshold_is_clamped_to_one(self):
        monitor = HealthMonitor(store=ObservabilityStore(), failure_threshold=0)
        api_id = register(monitor, "api", "service", probe=always_down)
        assert monitor.check_health(api_id)["status"] == ComponentStatus.UNHEALTHY.value


class TestNoProbeConfigured:
    def test_a_component_without_a_probe_reports_unknown(self, monitor):
        api_id = register(monitor, "api", "service")
        result = monitor.check_health(api_id)

        assert result["status"] == ComponentStatus.UNKNOWN.value
        assert result["error"] == "no probe configured"

    def test_unknown_is_not_healthy(self, monitor):
        """Not being able to check is not the same as being fine."""
        api_id = register(monitor, "api", "service")
        assert monitor.check_health(api_id)["status"] != ComponentStatus.HEALTHY.value

    def test_an_unregistered_component_reports_an_error(self, monitor):
        assert "error" in monitor.check_health("ghost")

    def test_a_probe_can_be_cleared(self, monitor):
        api_id = register(monitor, "api", "service", probe=always_up)
        assert monitor.check_health(api_id)["status"] == ComponentStatus.HEALTHY.value

        monitor.set_probe(api_id, None)
        assert monitor.check_health(api_id)["status"] == ComponentStatus.UNKNOWN.value


class TestProbeFailureContainment:
    def test_a_raising_probe_reports_unhealthy_rather_than_crashing(self, monitor):
        def explode() -> ProbeResult:
            raise RuntimeError("boom")

        api_id = register(monitor, "api", "service", probe=explode)
        result = monitor.check_health(api_id)

        assert result["status"] != ComponentStatus.HEALTHY.value
        assert "boom" in result["error"]

    def test_a_probe_returning_a_bare_bool_is_accepted(self, monitor):
        api_id = register(monitor, "api", probe=lambda: True)
        assert monitor.check_health(api_id)["status"] == ComponentStatus.HEALTHY.value

    def test_callable_probe_contains_exceptions(self):
        def explode():
            raise ValueError("nope")

        result = CallableProbe(explode)()
        assert result.healthy is False
        assert "ValueError" in result.error

    def test_callable_probe_treats_returning_none_as_success(self):
        assert CallableProbe(lambda: None)().healthy is True

    def test_callable_probe_treats_a_falsy_return_as_failure(self):
        result = CallableProbe(lambda: False)()
        assert result.healthy is False
        assert result.error is not None

    def test_callable_probe_preserves_a_returned_probe_result(self):
        original = ProbeResult(healthy=True, latency_ms=99.0, detail="custom")
        assert CallableProbe(lambda: original)() is original


class TestHttpProbe:
    def _transport(self, monkeypatch, status=None, error=None):
        import src.observability.probes as probes

        class FakeResponse:
            def __init__(self, code):
                self.status_code = code

        class FakeRequests:
            def get(self, url, timeout=None, verify=None):
                if error is not None:
                    raise error
                return FakeResponse(status)

        monkeypatch.setattr(probes, "requests", FakeRequests())

    def test_a_200_is_healthy(self, monkeypatch):
        self._transport(monkeypatch, status=200)
        assert HttpProbe("https://example.invalid/health")().healthy is True

    def test_a_204_is_healthy(self, monkeypatch):
        self._transport(monkeypatch, status=204)
        assert HttpProbe("https://example.invalid/health")().healthy is True

    def test_a_500_is_unhealthy(self, monkeypatch):
        self._transport(monkeypatch, status=500)
        result = HttpProbe("https://example.invalid/health")()
        assert result.healthy is False
        assert "500" in result.error

    def test_a_404_is_unhealthy(self, monkeypatch):
        self._transport(monkeypatch, status=404)
        assert HttpProbe("https://example.invalid/health")().healthy is False

    def test_a_connection_error_is_unhealthy(self, monkeypatch):
        self._transport(monkeypatch, error=ConnectionError("refused"))
        result = HttpProbe("https://example.invalid/health")()
        assert result.healthy is False
        assert "ConnectionError" in result.error

    def test_a_timeout_is_unhealthy(self, monkeypatch):
        self._transport(monkeypatch, error=TimeoutError("timed out"))
        assert HttpProbe("https://example.invalid/health")().healthy is False

    def test_custom_healthy_statuses(self, monkeypatch):
        self._transport(monkeypatch, status=418)
        probe = HttpProbe("https://example.invalid/health", healthy_statuses=(418,))
        assert probe().healthy is True

    def test_tls_verification_is_on_by_default(self):
        assert HttpProbe("https://example.invalid/health").verify_tls is True

    def test_a_timeout_is_always_set(self):
        assert HttpProbe("https://example.invalid/health").timeout > 0


class TestTcpProbe:
    def test_an_unreachable_port_is_unhealthy(self):
        # Port 1 on localhost is not listening in any sane environment.
        result = TcpProbe("127.0.0.1", 1, timeout=0.25)()
        assert result.healthy is False
        assert result.error is not None

    def test_an_unresolvable_host_is_unhealthy(self):
        result = TcpProbe("nonexistent.invalid", 80, timeout=0.25)()
        assert result.healthy is False

    def test_a_listening_socket_is_healthy(self):
        import socket

        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            assert TcpProbe("127.0.0.1", port, timeout=1.0)().healthy is True
        finally:
            server.close()


class TestDependencies:
    def test_dependency_health_comes_from_the_store(self, monitor):
        db_id = register(monitor, "db", "database", probe=always_up)
        monitor.check_health(db_id)

        api_id = register(
            monitor, "api", metadata={"dependencies": [db_id]}, probe=always_up
        )
        deps = monitor.check_dependencies(api_id)

        assert len(deps) == 1
        assert deps[0]["id"] == db_id
        assert deps[0]["status"] == ComponentStatus.HEALTHY.value

    def test_an_unhealthy_dependency_is_reported_as_such(self, monitor):
        db_id = register(monitor, "db", "database", probe=always_down)
        monitor.check_health(db_id)
        monitor.check_health(db_id)

        api_id = register(monitor, "api", metadata={"dependencies": [db_id]})
        deps = monitor.check_dependencies(api_id)
        assert deps[0]["status"] == ComponentStatus.UNHEALTHY.value

    def test_an_unregistered_dependency_reports_unknown(self, monitor):
        api_id = register(monitor, "api", metadata={"dependencies": ["ghost"]})
        deps = monitor.check_dependencies(api_id)

        assert deps[0]["status"] == ComponentStatus.UNKNOWN.value
        assert deps[0]["error"] == "dependency not registered"

    def test_no_declared_dependencies_returns_empty(self, monitor):
        api_id = register(monitor, "api", "service")
        assert monitor.check_dependencies(api_id) == []

    def test_an_unknown_component_returns_empty(self, monitor):
        assert monitor.check_dependencies("ghost") == []

    def test_dependencies_are_never_invented(self, monitor):
        """The old implementation always returned database, cache and queue."""
        api_id = register(monitor, "api", "service")
        deps = monitor.check_dependencies(api_id)

        assert {d.get("type") for d in deps} != {"database", "cache", "queue"}
        assert deps == []
