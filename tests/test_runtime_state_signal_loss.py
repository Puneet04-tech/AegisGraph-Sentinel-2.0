"""Tests that runtime state does not silently drop failure signals.

A dependency validation failure that could not be written to the audit log was
discarded entirely, and the shutdown-with-active-tasks invariant was computed
and then thrown away by a bare ``pass``.
"""

import pytest

from src.dependency import DependencyRule
from src.runtime.runtime_state import RuntimeState


class FakeTasks:
    """Stands in for TaskRegistry, whose active_count is read-only."""

    def __init__(self, active_count=0):
        self.active_count = active_count


@pytest.fixture
def state():
    return RuntimeState()


class TestInvariantWarnings:
    """Invariant 3 reaches the caller."""

    def test_clean_state_has_no_warnings(self, state):
        result = state.check_invariants()

        assert result["warnings"] == []
        assert result["valid"] is True

    def test_shutdown_with_active_tasks_warns(self, state):
        state.shutting_down = True
        state.tasks = FakeTasks(active_count=1)

        result = state.check_invariants()

        assert len(result["warnings"]) == 1
        assert "shutting down" in result["warnings"][0]

    def test_the_warning_is_not_a_hard_violation(self, state):
        state.shutting_down = True
        state.tasks = FakeTasks(active_count=3)

        result = state.check_invariants()

        # Tasks may legitimately be in cleanup, so this stays a warning.
        assert result["valid"] is True
        assert result["violations"] == []

    def test_shutdown_without_tasks_does_not_warn(self, state):
        state.shutting_down = True
        state.tasks = FakeTasks(active_count=0)

        assert state.check_invariants()["warnings"] == []

    def test_warnings_surface_in_metrics(self, state):
        state.shutting_down = True
        state.tasks = FakeTasks(active_count=2)

        metrics = state.get_metrics()

        assert metrics["invariants"]["warnings"]

    def test_hard_violations_are_still_reported(self, state):
        state.started = True
        state.shutting_down = True

        result = state.check_invariants()

        assert result["valid"] is False
        assert result["violations"]


class TestAuditWriteFailures:
    """A failed audit write is reported, not swallowed."""

    def test_audit_failure_is_logged(self, state, caplog, monkeypatch):
        from src.runtime import runtime_state as runtime_state_module

        def failing_audit(**kwargs):
            raise RuntimeError("audit backend unavailable")

        monkeypatch.setattr(runtime_state_module, "log_audit_event", failing_audit)

        # Register a dependency rule that cannot be satisfied so validation
        # produces a failure to audit.
        state.dependency_registry.register_dependency_rule(DependencyRule(
            service_name="reporting_service",
            required_dependencies=["definitely_not_registered"],
        ))

        with caplog.at_level("ERROR"):
            results = state.validate_runtime_dependencies()

        assert any(not r.valid for r in results)
        assert "audit event" in caplog.text

    def test_audit_failure_does_not_lose_the_validation_result(
        self, state, monkeypatch,
    ):
        from src.runtime import runtime_state as runtime_state_module

        monkeypatch.setattr(
            runtime_state_module, "log_audit_event",
            lambda **kwargs: (_ for _ in ()).throw(RuntimeError("down")),
        )

        state.dependency_registry.register_dependency_rule(DependencyRule(
            service_name="reporting_service",
            required_dependencies=["definitely_not_registered"],
        ))

        results = state.validate_runtime_dependencies()

        # The caller still receives the failures, and they are still recorded
        # on the runtime state.
        assert [r for r in results if not r.valid]
        assert [r for r in state.dependency_validation_results if not r.valid]

    def test_audit_failure_does_not_propagate(self, state, monkeypatch):
        from src.runtime import runtime_state as runtime_state_module

        monkeypatch.setattr(
            runtime_state_module, "log_audit_event",
            lambda **kwargs: (_ for _ in ()).throw(RuntimeError("down")),
        )

        state.dependency_registry.register_dependency_rule(DependencyRule(
            service_name="reporting_service",
            required_dependencies=["definitely_not_registered"],
        ))

        # Validation must survive an unavailable audit backend.
        assert state.validate_runtime_dependencies() is not None
