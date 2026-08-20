"""Regression test: archival scheduler shutdown failures must be logged, not swallowed."""

import asyncio

from src.api import main as api_main


def test_stop_runtime_background_tasks_logs_archival_failure(monkeypatch):
    """A failing archival scheduler stop() must not be reported as a clean shutdown."""

    class _BoomScheduler:
        def stop(self, timeout=5.0):
            raise RuntimeError("scheduler wedged")

    monkeypatch.setattr(
        "src.archival.scheduler.get_archival_scheduler", lambda: _BoomScheduler()
    )

    logged_events = []
    original_error = api_main._api_logger.error

    def _capture_error(message, event_type="error", metadata=None):
        logged_events.append(event_type)
        return original_error(message, event_type=event_type, metadata=metadata)

    monkeypatch.setattr(api_main._api_logger, "error", _capture_error)
    monkeypatch.setattr(api_main.state.tasks, "cancel_all_tasks", _noop_cancel)

    asyncio.run(api_main._stop_runtime_background_tasks())

    assert "shutdown_archival_error" in logged_events


async def _noop_cancel(timeout_seconds=10.0):
    return None
