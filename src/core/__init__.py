"""Core dependency injection infrastructure and service boundaries."""

from __future__ import annotations

from .dependency_container import DependencyContainer
from .service_registry import (
    register_core_services,
    register_graph_services,
    register_innovation_services,
)

__all__ = [
    "DependencyContainer",
    "register_core_services",
    "register_graph_services",
    "register_innovation_services",
]
