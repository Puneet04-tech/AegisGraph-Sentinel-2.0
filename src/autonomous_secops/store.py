"""
Autonomous SecOps Store.

Storage layer for autonomous security operations.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    Alert,
    AlertStatus,
    AuditEvent,
    CorrelationRule,
    Incident,
    IncidentStatus,
    Playbook,
    PlaybookExecution,
    PlaybookStatus,
    Severity,
    SOCMetrics,
    ThreatHunt,
)


class AutonomousSecOpsStore:
    """Store for autonomous secops."""

    def __init__(self) -> None:
        """Initialize the store."""
        self._alerts: Dict[str, Alert] = {}
        self._incidents: Dict[str, Incident] = {}
        self._playbooks: Dict[str, Playbook] = {}
        self._playbook_executions: Dict[str, PlaybookExecution] = {}
        self._threat_hunts: Dict[str, ThreatHunt] = {}
        self._correlation_rules: Dict[str, CorrelationRule] = {}
        self._audit_log: List[AuditEvent] = []
        self._lock = threading.RLock()

    def add_alert(self, alert: Alert) -> None:
        """Add an alert."""
        with self._lock:
            self._alerts[alert.alert_id] = alert

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get an alert."""
        return self._alerts.get(alert_id)

    def get_alerts_by_status(self, status: AlertStatus) -> List[Alert]:
        """Get alerts by status."""
        return [a for a in self._alerts.values() if a.status == status]

    def get_new_alerts(self) -> List[Alert]:
        """Get new alerts."""
        return self.get_alerts_by_status(AlertStatus.NEW)

    def update_alert(self, alert_id: str, updates: Dict[str, Any]) -> bool:
        """Update an alert."""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False
        for key, value in updates.items():
            if hasattr(alert, key):
                setattr(alert, key, value)
        return True

    def create_incident(self, incident: Incident) -> None:
        """Create an incident."""
        with self._lock:
            self._incidents[incident.incident_id] = incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get an incident."""
        return self._incidents.get(incident_id)

    def get_incidents_by_status(self, status: IncidentStatus) -> List[Incident]:
        """Get incidents by status."""
        return [i for i in self._incidents.values() if i.status == status]

    def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> bool:
        """Update an incident."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return False
        for key, value in updates.items():
            if hasattr(incident, key):
                setattr(incident, key, value)
        incident.updated_at = datetime.now(timezone.utc)
        return True

    def add_playbook(self, playbook: Playbook) -> None:
        """Add a playbook."""
        with self._lock:
            self._playbooks[playbook.playbook_id] = playbook

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        """Get a playbook."""
        return self._playbooks.get(playbook_id)

    def get_active_playbooks(self) -> List[Playbook]:
        """Get active playbooks."""
        return [p for p in self._playbooks.values() if p.status == PlaybookStatus.ACTIVE]

    def create_playbook_execution(self, execution: PlaybookExecution) -> None:
        """Create a playbook execution."""
        with self._lock:
            self._playbook_executions[execution.execution_id] = execution

    def get_playbook_execution(self, execution_id: str) -> Optional[PlaybookExecution]:
        """Get a playbook execution."""
        return self._playbook_executions.get(execution_id)

    def add_threat_hunt(self, hunt: ThreatHunt) -> None:
        """Add a threat hunt."""
        with self._lock:
            self._threat_hunts[hunt.hunt_id] = hunt

    def get_threat_hunt(self, hunt_id: str) -> Optional[ThreatHunt]:
        """Get a threat hunt."""
        return self._threat_hunts.get(hunt_id)

    def add_correlation_rule(self, rule: CorrelationRule) -> None:
        """Add a correlation rule."""
        with self._lock:
            self._correlation_rules[rule.rule_id] = rule

    def get_correlation_rule(self, rule_id: str) -> Optional[CorrelationRule]:
        """Get a correlation rule."""
        return self._correlation_rules.get(rule_id)

    def get_enabled_rules(self) -> List[CorrelationRule]:
        """Get enabled correlation rules."""
        return [r for r in self._correlation_rules.values() if r.enabled]

    def log_audit(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """Log an audit event."""
        event = AuditEvent(
            event_id=f"audit-{len(self._audit_log) + 1}",
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            success=success,
        )
        with self._lock:
            self._audit_log.append(event)

    def get_audit_log(self, limit: int = 100) -> List[AuditEvent]:
        """Get audit log."""
        return self._audit_log[-limit:]

    def get_metrics(self) -> SOCMetrics:
        """Get SOC metrics."""
        incidents = list(self._incidents.values())
        
        return SOCMetrics(
            total_incidents=len(incidents),
            open_incidents=len([
                i for i in incidents
                if i.status not in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]
            ]),
            resolved_incidents=len([
                i for i in incidents
                if i.status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]
            ]),
            alerts_processed=len(self._alerts),
            automated_responses=len([
                e for e in self._playbook_executions.values()
                if e.status == "completed"
            ]),
            calculated_at=datetime.now(timezone.utc),
        )

    def clear(self) -> None:
        """Clear all data."""
        with self._lock:
            self._alerts.clear()
            self._incidents.clear()
            self._playbooks.clear()
            self._playbook_executions.clear()
            self._threat_hunts.clear()
            self._correlation_rules.clear()
            self._audit_log.clear()


# Singleton instance
_store: Optional[AutonomousSecOpsStore] = None
_store_lock = threading.Lock()


def get_secops_store() -> AutonomousSecOpsStore:
    """Get the global store instance."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = AutonomousSecOpsStore()
    return _store


def reset_secops_store() -> None:
    """Reset the global store."""
    global _store
    with _store_lock:
        if _store is not None:
            _store.clear()
        _store = None