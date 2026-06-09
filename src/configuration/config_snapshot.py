"""Immutable diagnostic snapshots for configuration state."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping
from copy import deepcopy

from .config_registry import ConfigRegistry


@dataclass(frozen=True)
class ConfigSnapshot:
    timestamp: str
    values: Mapping[str, Any]

    @classmethod
    def capture(cls, registry: ConfigRegistry) -> "ConfigSnapshot":
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return cls(
            timestamp=timestamp,
            values=MappingProxyType(deepcopy(registry.values())),
        )
