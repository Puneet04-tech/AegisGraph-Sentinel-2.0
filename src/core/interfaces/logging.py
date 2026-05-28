"""Service boundary for logging and observability."""

from __future__ import annotations

from typing import Any, Dict, Protocol


class Logger(Protocol):
    """Protocol defining structured logging capabilities."""

    def debug(self, msg: str, event_type: str = ..., metadata: Dict[str, Any] = ...) -> None:
        ...

    def info(self, msg: str, event_type: str = ..., metadata: Dict[str, Any] = ...) -> None:
        ...

    def warning(self, msg: str, event_type: str = ..., metadata: Dict[str, Any] = ...) -> None:
        ...

    def error(self, msg: str, event_type: str = ..., metadata: Dict[str, Any] = ...) -> None:
        ...

    def critical(self, msg: str, event_type: str = ..., metadata: Dict[str, Any] = ...) -> None:
        ...
