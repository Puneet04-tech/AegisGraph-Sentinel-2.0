"""Service contract model."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ServiceContract:
    service_name: str
    required_methods: list[str] = field(default_factory=list)
