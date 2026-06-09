"""Lightweight configuration schema entries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass
class ConfigEntry:
    name: str
    value: Any
    default: Any = None
    required: bool = False
    expected_type: Optional[type] = None
    validator: Optional[Callable[[Any], bool]] = None
