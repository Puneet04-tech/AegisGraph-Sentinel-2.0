"""Regression coverage for non-blocking drift alert dispatch."""

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
