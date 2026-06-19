"""Runtime threat metrics helpers."""

from __future__ import annotations

from typing import Any, Dict

from .abuse_tracker import AbuseTracker
from .threat_registry import ThreatRegistry


class ThreatMetrics:
    def __init__(self, registry: ThreatRegistry, tracker: AbuseTracker) -> None:
        self.registry = registry
        self.tracker = tracker

    def active_threat_count(self) -> int:
        return len(self.registry.list_threats())

    def severity_counts(self) -> Dict[str, int]:
        return self.registry.count_by_severity()

    def tracked_event_counts(self) -> Dict[str, int]:
        return self.tracker.snapshot()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "active_threat_count": self.active_threat_count(),
            "severity_counts": self.severity_counts(),
            "tracked_event_counts": self.tracked_event_counts(),
        }
