"""Tests that defense grid failures are reported rather than swallowed.

A failing subscriber was discarded by ``except Exception: pass``, a failing
policy action aborted the whole response, and a command whose handler raised
propagated out while a command whose handler returned an error was still
stamped COMPLETED.
"""

import threading

import pytest

from src.defense_grid.controller import DefenseGridController
from src.defense_grid.store import DefenseStore


@pytest.fixture
def controller():
    return DefenseGridController(store=DefenseStore())


def make_command(command_type="BLOCK_IP"):
    from src.defense_grid.controller import DefenseCommand

    return DefenseCommand(
        command_id=f"cmd-{command_type}",
        command_type=command_type,
        target="entity-1",
    )


class TestSubscriberFailures:
    """A broken subscriber is logged, and does not stop the others."""

    def test_failure_is_logged_not_swallowed(self, controller, caplog):
        def broken(event):
            raise RuntimeError("subscriber down")

        controller.subscribe(broken)

        with caplog.at_level("WARNING"):
            controller._notify_subscribers({"type": "TEST_EVENT"})

        assert "subscriber" in caplog.text.lower()

    def test_one_failure_does_not_starve_other_subscribers(self, controller):
        received = []

        controller.subscribe(lambda event: (_ for _ in ()).throw(RuntimeError("x")))
        controller.subscribe(received.append)

        controller._notify_subscribers({"type": "TEST_EVENT"})

        assert len(received) == 1

    def test_healthy_subscribers_receive_the_event(self, controller):
        received = []
        controller.subscribe(received.append)

        controller._notify_subscribers({"type": "CONTAINMENT_INITIATED"})

        assert received == [{"type": "CONTAINMENT_INITIATED"}]

    def test_subscribing_during_notification_does_not_break_iteration(self, controller):
        # The list is snapshotted under the lock, so a subscriber added from
        # another thread mid-notification cannot corrupt the iteration.
        errors = []

        def adder(event):
            def late(_):
                pass
            thread = threading.Thread(target=controller.subscribe, args=(late,))
            thread.start()
            thread.join()

        controller.subscribe(adder)

        try:
            controller._notify_subscribers({"type": "TEST_EVENT"})
        except RuntimeError as exc:  # pragma: no cover - regression guard
            errors.append(exc)

        assert errors == []


class TestPolicyActionFailures:
    """One failing action does not abort the rest of the response."""

    def _policy(self, actions):
        return {
            "policy_id": "p1",
            "actions": actions,
            "cooldown_seconds": 0,
        }

    def test_remaining_actions_still_run(self, controller):
        ran = []

        controller.register_handler("GOOD", lambda action: ran.append("good") or "ok")
        controller.register_handler(
            "BAD", lambda action: (_ for _ in ()).throw(RuntimeError("boom")),
        )

        result = controller._execute_policy(self._policy([
            {"type": "BAD"}, {"type": "GOOD"},
        ]))

        assert ran == ["good"]
        assert result["actions_executed"] == 1
        assert result["actions_failed"] == 1

    def test_failure_detail_is_reported(self, controller):
        controller.register_handler(
            "BAD", lambda action: (_ for _ in ()).throw(RuntimeError("boom")),
        )

        result = controller._execute_policy(self._policy([{"type": "BAD"}]))

        assert result["failures"][0]["action_type"] == "BAD"
        assert "boom" in result["failures"][0]["error"]

    def test_all_succeeding_reports_no_failures(self, controller):
        controller.register_handler("GOOD", lambda action: "ok")

        result = controller._execute_policy(self._policy([
            {"type": "GOOD"}, {"type": "GOOD"},
        ]))

        assert result["actions_executed"] == 2
        assert result["failures"] == []

    def test_unhandled_action_types_are_skipped(self, controller):
        result = controller._execute_policy(self._policy([{"type": "UNKNOWN"}]))

        assert result["actions_executed"] == 0
        assert result["actions_failed"] == 0


class TestCommandExecution:
    """A command that fails is recorded as failed."""

    def test_failing_handler_marks_the_command_failed(self, controller):
        controller.register_handler(
            "BLOCK_IP", lambda command: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        command = make_command()
        controller.queue_command(command)

        result = controller.execute_command(command.command_id)

        assert result["status"] == "FAILED"
        assert command.status == "FAILED"

    def test_failing_handler_does_not_propagate(self, controller):
        controller.register_handler(
            "BLOCK_IP", lambda command: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        command = make_command()
        controller.queue_command(command)

        # Must return a result rather than taking down the caller.
        assert "error" in controller.execute_command(command.command_id)

    def test_successful_handler_still_completes(self, controller):
        controller.register_handler("BLOCK_IP", lambda command: {"blocked": True})
        command = make_command()
        controller.queue_command(command)

        result = controller.execute_command(command.command_id)

        assert result["status"] == "COMPLETED"
        assert command.status == "COMPLETED"
        assert result["result"] == {"blocked": True}

    def test_missing_handler_is_still_reported(self, controller):
        command = make_command("NO_HANDLER")
        controller.queue_command(command)

        assert "error" in controller.execute_command(command.command_id)

    def test_unknown_command_is_reported(self, controller):
        assert "error" in controller.execute_command("no-such-command")
