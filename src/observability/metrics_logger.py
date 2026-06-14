"""Lightweight metrics event logging."""

from typing import Any, Dict, Optional

from .structured_logger import StructuredLogger, get_logger


class MetricsLogger:
    """Emit timing and counter-style events as structured logs."""

    def __init__(self, module: str = "metrics") -> None:
        self._logger: StructuredLogger = get_logger(module)

    def record_timing(
        self,
        metric_name: str,
        duration_ms: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._logger.info(
            f"Metric {metric_name}",
            event_type="metric_timing",
            metadata={
                "metric_name": metric_name,
                "duration_ms": duration_ms,
                **(metadata or {}),
            },
        )

    def record_counter(
        self,
        metric_name: str,
        value: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._logger.info(
            f"Counter {metric_name}",
            event_type="metric_counter",
            metadata={
                "metric_name": metric_name,
                "value": value,
                **(metadata or {}),
            },
        )

prometheus_export_enabled = True

