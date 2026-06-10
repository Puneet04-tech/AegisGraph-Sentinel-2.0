"""Service dependency rule model."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DependencyRule:
    service_name: str
    required_dependencies: list[str] = field(default_factory=list)
    optional_dependencies: list[str] = field(default_factory=list)
