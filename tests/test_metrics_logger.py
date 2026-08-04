"""Dedicated unit tests for src/observability/metrics_logger.py.

``MetricsLogger`` emits timing and counter events as structured log lines but
had no direct unit coverage.  These tests pin the emitted event types and
metadata payloads via an injected recording logger.
"""

import pytest

from src.observability.metrics_logger import MetricsLogger, prometheus_export_enabled


class _RecordingLogger:
    def __init__(self) -> None:
        self.calls: list = []

    def info(self, message, event_type="info", metadata=None) -> None:
        self.calls.append((message, event_type, metadata))


@pytest.fixture
def logger() -> MetricsLogger:
    metrics = MetricsLogger("metrics-test")
    metrics._logger = _RecordingLogger()
    return metrics


def test_record_timing_emits_timing_event(logger):
    logger.record_timing("inference_latency", 12.5, metadata={"model": "htgnn"})
    _, event_type, metadata = logger._logger.calls[0]
    assert event_type == "metric_timing"
    assert metadata["metric_name"] == "inference_latency"
    assert metadata["duration_ms"] == 12.5
    assert metadata["model"] == "htgnn"


def test_record_counter_defaults_to_one(logger):
    logger.record_counter("alerts_raised")
    _, event_type, metadata = logger._logger.calls[0]
    assert event_type == "metric_counter"
    assert metadata["metric_name"] == "alerts_raised"
    assert metadata["value"] == 1.0


def test_record_counter_with_explicit_value(logger):
    logger.record_counter("alerts_raised", value=3, metadata={"severity": "high"})
    _, _, metadata = logger._logger.calls[0]
    assert metadata["value"] == 3
    assert metadata["severity"] == "high"


def test_prometheus_export_enabled_default():
    assert prometheus_export_enabled is True
