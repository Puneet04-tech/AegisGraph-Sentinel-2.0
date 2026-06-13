"""Thread-safe in-memory configuration registry."""

from __future__ import annotations

from copy import deepcopy
from threading import RLock
from typing import Any, Dict, List, Optional

from .config_schema import ConfigEntry


class ConfigRegistry:
    """Single in-memory source of truth for runtime configuration."""

    def __init__(self) -> None:
        self._entries: Dict[str, ConfigEntry] = {}
        self._lock = RLock()

    def register(
        self,
        name: str,
        value: Any,
        *,
        default: Any = None,
        required: bool = False,
        expected_type: Optional[type] = None,
        validator: Any = None,
    ) -> ConfigEntry:
        with self._lock:
            entry = ConfigEntry(
                name=name,
                value=value,
                default=default,
                required=required,
                expected_type=expected_type,
                validator=validator,
            )
            self._entries[name] = entry
            return deepcopy(entry)

    def get(self, name: str) -> Any:
        with self._lock:
            return self._entries[name].value

    def get_entry(self, name: str) -> ConfigEntry:
        with self._lock:
            return deepcopy(self._entries[name])

    def update(self, name: str, value: Any) -> ConfigEntry:
        with self._lock:
            entry = self._entries[name]
            entry.value = value
            return deepcopy(entry)

    def exists(self, name: str) -> bool:
        with self._lock:
            return name in self._entries

    def list_configs(self) -> List[ConfigEntry]:
        with self._lock:
            return deepcopy(list(self._entries.values()))

    def values(self) -> Dict[str, Any]:
        with self._lock:
            return {name: deepcopy(entry.value) for name, entry in self._entries.items()}

    def _restore_values(self, values: Dict[str, Any]) -> None:
        with self._lock:
            for name, value in values.items():
                if name in self._entries:
                    self._entries[name].value = value
