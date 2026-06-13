"""Small incident manager with optional containment and audit hooks."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Set

from ...audit import log_audit_event
from .containment import ContainmentManager
from .incident import Incident
from .incident_registry import IncidentRegistry


class IncidentManager:
    def __init__(
        self,
        registry: Optional[IncidentRegistry] = None,
        containment: Optional[ContainmentManager] = None,
        audit_logger: Optional[Callable[..., Any]] = log_audit_event,
        containment_severities: Optional[Set[str]] = None,
    ) -> None:
        self.registry = registry or IncidentRegistry()
        self.containment = containment or ContainmentManager()
        self.audit_logger = audit_logger
        self.containment_severities = containment_severities or {"high", "critical"}

    def create_incident(
        self,
        incident_type: str,
        severity: str,
        metadata: Optional[Dict[str, Any]] = None,
        trigger_containment: Optional[bool] = None,
    ) -> Incident:
        normalized_severity = severity.lower()
        should_contain = (
            normalized_severity in self.containment_severities
            if trigger_containment is None
            else trigger_containment
        )
        incident = self.registry.create_incident(
            incident_type=incident_type,
            severity=normalized_severity,
            metadata=metadata,
            contained=should_contain,
        )
        if should_contain:
            self.containment.activate_containment()
        self._audit_incident(incident)
        return incident

    def release_containment(self) -> Dict[str, bool]:
        return self.containment.deactivate_containment()

    def get_metrics(self) -> Dict[str, Any]:
        incidents = self.registry.list_incidents()
        return {
            "total": len(incidents),
            "by_severity": self.registry.count_by_severity(),
            "contained": sum(1 for incident in incidents if incident.contained),
            "containment": self.containment.get_flags(),
        }

    def _audit_incident(self, incident: Incident) -> None:
        if self.audit_logger is None:
            return
        try:
            self.audit_logger(
                event_type="security_incident_created",
                severity=incident.severity,
                source="security_incident_manager",
                metadata={
                    "incident_id": incident.incident_id,
                    "incident_type": incident.incident_type,
                    "contained": incident.contained,
                },
            )
        except Exception:
            pass
