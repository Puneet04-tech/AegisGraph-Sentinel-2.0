"""Lightweight runtime service registry."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from ..observability import get_logger
from ..core.dependency_container import DependencyContainer

_MISSING = object()


@dataclass(frozen=True)
class ServiceInfo:
    name: str
    initialized: bool
    service_type: str


class ServiceContainer(DependencyContainer):
    """Small registry for initialized services without a DI framework."""

    def __init__(self, logger: Any = None) -> None:
        super().__init__()
        self._logger = logger or get_logger("runtime.service_container")

    def register_service(self, name: str, service: Any, *, replace: bool = False) -> Any:
        self.register(name, service, replace=replace)
        self._logger.info(
            "Runtime service registered",
            event_type="runtime_service_registered",
            metadata={"service": name, "service_type": type(service).__name__},
        )
        return service

    def get_service(self, name: str, default: Any = _MISSING, *, required: bool = False) -> Any:
        val = self.optional_get(name)
        if val is not None:
            return val
        if required or default is _MISSING:
            raise KeyError(f"Runtime service is not initialized: {name}")
        return default

    def has_service(self, name: str) -> bool:
        return self.has(name)

    def optional_service(self, name: str) -> Any:
        return self.optional_get(name)

    def get_initialization_state(self) -> List[ServiceInfo]:
        with self._lock:
            return [
                ServiceInfo(name=name, initialized=service is not None, service_type=type(service).__name__)
                for name, service in sorted(self._services.items())
            ]

