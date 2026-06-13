"""
Security Operations Engine.

Core engine for autonomous security operations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import Alert, AlertStatus, Incident, IncidentStatus, Severity
from .store import AutonomousSecOpsStore, get_secops_store


class SecurityOperationsEngine:
    """Core security operations engine."""

    def __init__(self, store: Optional[AutonomousSecOpsStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_secops_store()

    def process_alert(
        self,
        title: str,
        description: str,
        severity: str,
        source: str,
        indicators: Optional[List[Dict[str, Any]]] = None,
    ) -> Alert:
        """Process a new alert."""
        alert_id = f"alert-{uuid.uuid4().hex[:12]}"
        
        severity_enum = Severity(severity)
        
        alert = Alert(
            alert_id=alert_id,
            title=title,
            description=description,
            severity=severity_enum,
            source=source,
            indicators=indicators or [],
        )
        
        self.store.add_alert(alert)
        
        self.store.log_audit(
            user_id="system",
            action="alert_processed",
            resource_type="alert",
            resource_id=alert_id,
            details={"severity": severity, "source": source},
        )
        
        return alert

    def triage_alert(self, alert_id: str) -> Dict[str, Any]:
        """Triage an alert."""
        alert = self.store.get_alert(alert_id)
        if not alert:
            return {"success": False, "error": "Alert not found"}
        
        triage_score = self._calculate_triage_score(alert)
        
        alert.triage_score = triage_score
        alert.status = AlertStatus.TRIAGED
        
        should_escalate = triage_score >= 0.7
        
        if should_escalate:
            alert.status = AlertStatus.ESCALATED
        
        self.store.log_audit(
            user_id="system",
            action="alert_triaged",
            resource_type="alert",
            resource_id=alert_id,
            details={"triage_score": triage_score},
        )
        
        return {
            "success": True,
            "alert_id": alert_id,
            "triage_score": triage_score,
            "escalated": should_escalate,
        }

    def _calculate_triage_score(self, alert: Alert) -> float:
        """Calculate triage score."""
        score = 0.0
        
        severity_scores = {
            Severity.CRITICAL: 0.9,
            Severity.HIGH: 0.7,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.3,
            Severity.INFO: 0.1,
        }
        score = severity_scores.get(alert.severity, 0.5)
        
        score += len(alert.indicators) * 0.05
        
        if alert.source in ["siem", "edr", "firewall"]:
            score += 0.1
        
        return min(0.99, score)

    def create_incident_from_alert(self, alert_id: str) -> Optional[Incident]:
        """Create an incident from an alert."""
        alert = self.store.get_alert(alert_id)
        if not alert:
            return None
        
        incident_id = f"inc-{uuid.uuid4().hex[:12]}"
        
        incident = Incident(
            incident_id=incident_id,
            title=f"Incident: {alert.title}",
            description=alert.description,
            severity=alert.severity,
            status=IncidentStatus.NEW,
            alerts=[alert_id],
        )
        
        self.store.create_incident(incident)
        
        alert.status = AlertStatus.INCIDENT
        
        self.store.log_audit(
            user_id="system",
            action="incident_created",
            resource_type="incident",
            resource_id=incident_id,
            details={"alert_id": alert_id},
        )
        
        return incident

    def update_incident_status(
        self,
        incident_id: str,
        status: str,
    ) -> bool:
        """Update incident status."""
        status_enum = IncidentStatus(status)
        
        updates = {"status": status_enum}
        if status_enum == IncidentStatus.RESOLVED:
            updates["resolved_at"] = datetime.now(timezone.utc)
        
        return self.store.update_incident(incident_id, updates)

    def get_incident_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get incident timeline."""
        incident = self.store.get_incident(incident_id)
        if not incident:
            return []
        return incident.timeline

    def add_timeline_event(
        self,
        incident_id: str,
        event_type: str,
        description: str,
        user_id: str = "system",
    ) -> bool:
        """Add event to incident timeline."""
        incident = self.store.get_incident(incident_id)
        if not incident:
            return False
        
        event = {
            "type": event_type,
            "description": description,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
        }
        
        incident.timeline.append(event)
        incident.updated_at = datetime.now(timezone.utc)
        return True

    def get_dashboard(self) -> Dict[str, Any]:
        """Get operations dashboard."""
        metrics = self.store.get_metrics()
        alerts = list(self.store._alerts.values())
        incidents = list(self.store._incidents.values())
        
        return {
            "total_alerts": len(alerts),
            "new_alerts": len([a for a in alerts if a.status == AlertStatus.NEW]),
            "escalated_alerts": len([a for a in alerts if a.status == AlertStatus.ESCALATED]),
            "total_incidents": metrics.total_incidents,
            "open_incidents": metrics.open_incidents,
            "resolved_incidents": metrics.resolved_incidents,
            "automated_responses": metrics.automated_responses,
        }


# Singleton instance
_engine: Optional[SecurityOperationsEngine] = None


def get_secops_engine() -> SecurityOperationsEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = SecurityOperationsEngine()
    return _engine


def reset_secops_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None