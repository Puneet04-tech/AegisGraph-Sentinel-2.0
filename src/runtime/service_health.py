"""Model for service and task health status."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ServiceHealth:
    """Lightweight metadata modeling a service's runtime health status."""

    name: str
    status: str  # "healthy", "degraded", "unhealthy"
    last_heartbeat: float
    failures: int = 0
    restart_attempts: int = 0
    last_error: Optional[str] = None
    #: Whether the service is expected to publish heartbeats. Lazily created
    #: managers are tracked for visibility but never heartbeat, so the watchdog
    #: must not fail them for going quiet.
    heartbeat_required: bool = True
