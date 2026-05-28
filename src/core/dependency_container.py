"""Thread-safe lightweight service container."""

from __future__ import annotations

import threading
from typing import Any, Dict, Optional


class DependencyContainer:
    """Lightweight, thread-safe service container for dependency injection."""

    def __init__(self) -> None:
        self._services: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def register(self, name: str, instance: Any, replace: bool = False) -> None:
        """Register a service instance in the container."""
        with self._lock:
            if name in self._services and not replace:
                raise KeyError(f"Service '{name}' is already registered. Use replace=True to overwrite.")
            self._services[name] = instance

    def get(self, name: str) -> Any:
        """Retrieve a required service from the container.

        Raises KeyError if the service is not found or is set to None.
        """
        with self._lock:
            if name not in self._services or self._services[name] is None:
                raise KeyError(f"Required service '{name}' is not registered or is not available.")
            return self._services[name]

    def has(self, name: str) -> bool:
        """Check if a service is registered and is not None."""
        with self._lock:
            return name in self._services and self._services[name] is not None

    def optional_get(self, name: str) -> Optional[Any]:
        """Retrieve a service, returning None if not found or if set to None."""
        with self._lock:
            return self._services.get(name)
