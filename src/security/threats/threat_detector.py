"""Simple threshold-based runtime threat detector."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from ...audit import log_audit_event
from .abuse_tracker import AbuseTracker
from .threat import Threat
from .threat_registry import ThreatRegistry

DEFAULT_THRESHOLDS: Dict[int, str] = {
    5: "medium",
    10: "high",
    20: "critical",
}


class ThreatDetector:
    def __init__(
        self,
        registry: ThreatRegistry,
        tracker: AbuseTracker,
        *,
        thresholds: Optional[Dict[int, str]] = None,
        incident_manager: Optional[Any] = None,
        audit_logger: Optional[Callable[..., Any]] = log_audit_event,
    ) -> None:
        self.registry = registry
        self.tracker = tracker
        self.thresholds = dict(thresholds or DEFAULT_THRESHOLDS)
        self.incident_manager = incident_manager
        self.audit_logger = audit_logger

    def detect(self, event_type: str) -> Optional[Threat]:
        count = self.tracker.record_event(event_type)
        severity = self.thresholds.get(count)
        if severity is None:
            return None

        threat = Threat(
            threat_id=str(uuid.uuid4()),
            threat_type=event_type,
            severity=severity,
            created_at=datetime.now(timezone.utc),
            metadata={"event_type": event_type, "count": count},
        )
        self.registry.add_threat(threat)
        self._audit("abuse_pattern_detected", threat)
        self._audit("threat_detected", threat)
        if severity in {"high", "critical"}:
            self._audit("threat_escalated", threat)
        self._create_incident(threat)
        return threat

    def _create_incident(self, threat: Threat) -> None:
        if threat.severity not in {"high", "critical"} or self.incident_manager is None:
            return
        try:
            self.incident_manager.create_incident(
                incident_type="runtime_threat_detected",
                severity=threat.severity,
                metadata={
                    "threat_id": threat.threat_id,
                    "threat_type": threat.threat_type,
                    **threat.metadata,
                },
            )
        except Exception:
            pass

    def _audit(self, event_type: str, threat: Threat) -> None:
        if self.audit_logger is None:
            return
        try:
            self.audit_logger(
                event_type=event_type,
                severity=threat.severity,
                source="runtime_threat_detector",
                metadata={
                    "threat_id": threat.threat_id,
                    "threat_type": threat.threat_type,
                    **threat.metadata,
                },
            )
        except Exception:
            pass
