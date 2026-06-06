"""Structured JSON logging with request/correlation context."""

from __future__ import annotations

import json
import logging
import sys
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..security import safe_log_metadata

_request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
_correlation_id_var: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)


def generate_request_id() -> str:
    return f"req_{uuid.uuid4().hex[:12]}"


def get_request_id() -> Optional[str]:
    return _request_id_var.get()


def get_correlation_id() -> Optional[str]:
    return _correlation_id_var.get()


def set_request_context(
    request_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> None:
    if request_id is not None:
        _request_id_var.set(request_id)
    if correlation_id is not None:
        _correlation_id_var.set(correlation_id)


def clear_request_context() -> None:
    _request_id_var.set(None)
    _correlation_id_var.set(None)


class StructuredLogger:
    """Machine-readable JSON logger with request context propagation."""

    def __init__(self, module: str, level: int = logging.INFO) -> None:
        self.module = module
        self._logger = logging.getLogger(f"aegis.{module}")
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)
            self._logger.propagate = False
        self._logger.setLevel(level)

    def _emit(
        self,
        severity: str,
        message: str,
        event_type: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "request_id": get_request_id(),
            "correlation_id": get_correlation_id(),
            "module": self.module,
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "metadata": safe_log_metadata(metadata),
        }
        line = json.dumps(record, default=str)
        level = getattr(logging, severity.upper(), logging.INFO)
        self._logger.log(level, line)

    def info(self, message: str, event_type: str = "info", metadata: Optional[Dict[str, Any]] = None) -> None:
        self._emit("INFO", message, event_type, metadata)

    def warning(self, message: str, event_type: str = "warning", metadata: Optional[Dict[str, Any]] = None) -> None:
        self._emit("WARNING", message, event_type, metadata)

    def error(self, message: str, event_type: str = "error", metadata: Optional[Dict[str, Any]] = None) -> None:
        self._emit("ERROR", message, event_type, metadata)

    def audit(self, message: str, event_type: str = "audit", metadata: Optional[Dict[str, Any]] = None) -> None:
        self._emit("AUDIT", message, event_type, metadata)


def get_logger(module: str) -> StructuredLogger:
    return StructuredLogger(module)
