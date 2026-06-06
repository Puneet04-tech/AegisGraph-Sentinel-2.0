"""Centralized runtime resource limit defaults."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ResourceLimits:
    """Small, in-memory runtime resource limits."""

    max_runtime_tasks: int = 100
    max_event_queue_size: int = 256
    max_recovery_attempts_per_window: int = 5
    max_events_per_window: int = 1000
    memory_warning_threshold_mb: int = 512
    window_seconds: float = 60.0

