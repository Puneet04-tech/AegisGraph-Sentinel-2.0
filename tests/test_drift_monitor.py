"""Regression coverage for non-blocking drift alert dispatch."""

import logging
import importlib
import sys

from src.mlops.drift_monitor import AdversarialDriftMonitor


class _RecordingExecutor:
    def __init__(self):
        self.calls = []

    def submit(self, fn, *args, **kwargs):
        self.calls.append((fn, args, kwargs))
        return object()


def test_trigger_alert_submits_webhook_work():
    monitor = AdversarialDriftMonitor(webhook_url="https://example.invalid/webhook")
    monitor._alert_executor = _RecordingExecutor()

    monitor.trigger_alert("keystroke_flight_time", 1.0e-6, 0.42)

    assert len(monitor._alert_executor.calls) == 1
    fn, args, kwargs = monitor._alert_executor.calls[0]
    assert fn.__name__ == "_dispatch_webhook_alert"
    assert "Feature: keystroke_flight_time" in args[0]
    assert kwargs == {}


def test_monitor_uses_multi_worker_executor_and_closes_cleanly():
    monitor = AdversarialDriftMonitor(webhook_url="https://example.invalid/webhook", alert_workers=3)

    assert monitor._alert_executor._max_workers == 3
    assert monitor._closed is False

    monitor.close()

    assert monitor._closed is True
    assert monitor._alert_executor._shutdown is True


# ────────────────────────────────────────────────────────────
# Regression: importing drift_monitor must not install any
# handlers on the root logger.  A previous version called
# logging.basicConfig() at module scope which clobbered the
# root logger for any importer, depending on import order.
# ────────────────────────────────────────────────────────────

def test_importing_drift_monitor_does_not_modify_root_logger():
    """Importing drift_monitor must not install root-logger handlers.

    logging.basicConfig() at module level is forbidden in library code
    because it clobbers the root logger for the entire application,
    breaking structured JSON logging and log aggregation pipelines.
    """
    root_logger = logging.getLogger()
    handlers_before = list(root_logger.handlers)

    # Force a fresh import even if the module is already cached.
    mod_name = "src.mlops.drift_monitor"
    if mod_name in sys.modules:
        importlib.reload(sys.modules[mod_name])
    else:
        importlib.import_module(mod_name)

    handlers_after = list(root_logger.handlers)

    assert len(handlers_after) == len(handlers_before), (
        f"drift_monitor added {len(handlers_after) - len(handlers_before)} handler(s) "
        "to the root logger on import. Remove logging.basicConfig() from module scope — "
        "logging configuration must be done by the application entry point."
    )


def test_drift_monitor_uses_named_module_logger():
    """drift_monitor must use logging.getLogger(__name__), not the root logger directly."""
    import src.mlops.drift_monitor as dm_module

    assert hasattr(dm_module, "logger"), (
        "drift_monitor module must expose a module-level 'logger' "
        "created with logging.getLogger(__name__)."
    )
    assert dm_module.logger.name == "src.mlops.drift_monitor", (
        f"Expected logger named 'src.mlops.drift_monitor', got '{dm_module.logger.name}'. "
        "Use logging.getLogger(__name__) to get the correct module-scoped logger."
    )
